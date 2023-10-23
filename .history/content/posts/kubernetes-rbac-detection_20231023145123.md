---
author: HappyDog
title: 对Kubernetes RBAC授权防御&攻击的部分思考
date: 2023-06-20
tags:
  - CloudNative
  - RBAC
  - Defense
  - Kubernetes
categories:
  - Security
##
## Options for overriding site defaults
##
---

# 写在前面
不久前看到一篇对Kubernetes授权管理的文章，笔者而后进行一些实验和思考，因此诞生了这篇学习笔记。本文章思路未必贴合实际应用场景，有概念错误的地方还望多多指正。

首先笔者对于Kubernetes用户的授权分为两个抽象主体：对「基础设施」的权限授予和对「服务」的权限授予。

# 分类讨论
## 0x01-基础设施

「基础设施」的权限，理想情况下按照集群结构划分：

1. master节点使用admin用户账户权限，意即管理员权限
2. node节点使用普通用户权限，普通用户权限仅能对集群中的部分资源控制，或者是对某个namespcace中的资源进行控制

## 0x02-服务

什么又叫做对「服务」进行划分呢？云计算的初衷是优雅地调配庞大规模的服务群，那么运维人员就需要对A、B、C…这些服务（Service）能够操纵集群权限这个能力进行考量，假如Service A由三台nginx容器构成，可能就不需要什么集群服务的资源。对于B服务而言，其定位是用来监控集群主机健康状态的，所以就需要很强的「CURD」权限，起码是对「Pod」、「Deployment」有管理权限。

在「Kubernetes」中，每个服务容器都会被「kubelet」下发一个默认的「ServiceAccount」账户（后文简称SA），而运维人员可以指定服务容器注入哪个SA账户。这意味着运维人员可以将不同SA账户注入给各类服务容器，来达到各类服务（A、B、C）权限细粒度化。

## 0x03-归根到底
「基础设施」和「服务」的权限授予有相同之处，但又不完全相同。相同的地方在于概念，都是为了控制对集群资源操纵的能力，这一过程在「Kubernetes」中叫做「授权（Authoriazation）」，可以参考下图；不同的地方在于控制单元，基础设施的权限是以「用户账户（User Account）」的权限为单位的，而服务的权限是以「SA账户(ServiceAccount)」为单位划分的。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled.png)

那么，有没有办法来优雅地控制对这两种权限授予方式的统一呢？答案很显然是有，而且不止一种。这里摘取一种比较好的做法：通过「ClusterRole」分发权限。

例如管理员事先建立「Pod-read-Rule」、「Pod-Write-Rule」规则，分别用来制约对Pod容器可读、可写这两种「操作」，当然集群的资源可不止有Pod容器，我们可以通过「kubectl api-resources」例举哪些资源可以被「ClusterRole」约束。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-1.png)

而后，通过「RoleBinding」或者「ClusterBinding」的方式将这两个「ClusterRole」分发给不同的「User Account」或者「ServiceAccount」，相当于是把锅碗瓢盆给到不同的角色。

假设一个场景，当「User Account A」需要拥有所有Pod的可读权限，那么管理员（kubernetes admin）就通过「RoleBinding」的形式将「Pod-read-Rule」绑定给「User Account A」；当「User Account A」再想要要所有Pod的可写权限时，以相同的「RoleBinding」方式将「Pod-Write-Rule」绑定给「User Account A」即可。

最终，我们创建一个理想化的场景：把集群内所有可利用资源（api-resources）的「CURD」操作分别建立为不同的「ClusterRole」，在创建「Service Account」与「User Account」时赋予它们最小权限，指定最少范围的「namespace」，最好只作用于default namespcace。而后当「SA」或者「UA」需要对应权限时，管理员再经过审核制「RoleBinding」，分配「ClusterRole」给这些「SA」或者「UA」，而不是在初始化时就把权限塞满。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-2.png)

# 实践

下面以两个实践为例，理解前文提到的权限分发思路。表格为实验拓扑：一台Centos7.x作为Master节点，剩下两台作为Node节点

| 主机 | IP地址 | 内核版本 | 用户账户 |
| --- | --- | --- | --- |
| k8s-master | 192.168.56.80 | 3.10.0-1160.el7.x86_64 | kubernetes-admin |
| k8s-node1 | 192.168.56.81 | 3.10.0-1160.el7.x86_64 | userA |
| k8s-node2 | 192.168.56.82 | 3.10.0-1160.el7.x86_64 | userB |

## 实践场景1-使用UserAccount

master节点使用kubernetes-admin用户进行管理，其他两个node节点使用userA、userB用户进行管理，且需要满足的条件：

- kubernetes-admin具有对集群操纵的全部权限
- userA用户仅拥有对tenantA命名空间的Pod容器完全操作权限
- userB用户仅拥有对tenantB命名空间的Pod容器完全操作权限

---

分析：由于「master」节点的用户配置文件「/etc/kubernetes/admin.conf」默认为kubernetes-admin权限，所以我们无需关心，只需满足UserA、B的需求。

第一步：建立两个Kubernetes User Account分别为userA、userB，参考文章：[k8s创建用户账号——User Account - fat_girl_spring - 博客园 (cnblogs.com)](https://www.cnblogs.com/fat-girl-spring/p/14586259.html)。完整的创建过程如下，以相同的方式创建两个用户即可

```bash
[root@k8s-master tenantA]# (umask 077;openssl genrsa -out userA.key 2048)
[root@k8s-master tenantA]# openssl req -new -key userA.key -out userA.csr -subj "/O=k8s/CN=userA"
[root@k8s-master tenantA]# openssl  x509 -req -in userA.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out userA.crt -days 365

[root@k8s-master tenantA]# kubectl config set-cluster k8s --server=https://192.168.56.80:6443 --certificate-authority=/etc/kubernetes/pki/ca.crt --embed-certs=true --kubeconfig=/root/k8s_tenants/userA/userA.conf

[root@k8s-master tenantA]# kubectl config set-credentials userA --client-certificate=userA.crt --client-key=userA.key --embed-certs=true --kubeconfig=/root/k8s_tenants/userA/userA.conf

[root@k8s-master tenantA]# kubectl config set-context kubernetes-userA@k8s --cluster=k8s --user=userA --kubeconfig=/root/k8s_tenants/userA/userA.conf

[root@k8s-master tenantA]# kubectl config use-context kubernetes-userA@k8s --kubeconfig=/root/k8s_tenants/userA/userA.conf

[root@k8s-master tenantA]# kubectl get pods --kubeconfig ./userA.conf
```

第二步：创建两个「namespace」给「userA」、「userB」使用，这里笔者模拟的场景是租户根据「namespace」隔离

```bash
[root@k8s-master ~]# kubectl create namespace tenant-a
namespace/tanent-a created
[root@k8s-master ~]# kubectl create namespace tenant-b
namespace/tanent-b created
```

第三步：创建「ClusterRole」描述Pod容器完全操作权限

```yaml
# cluster_pod_all_permission_role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-pod-all-permission-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "update", "delete"]
```

第四步：分别将「cluster-pod-all-permission-role」权限绑定给用户A/B，并指定相对应的命名空间

```yaml
# usera_pod_rolebiding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenanta-pod-all-permission-role-binding
  namespace: tenant-a
subjects:
- kind: User
  name: userA
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-pod-all-permission-role
  apiGroup: rbac.authorization.k8s.io
---
# userb_pod_rolebiding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenantb-pod-all-permission-role-binding
  namespace: tenant-b
subjects:
- kind: User
  name: userB
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-pod-all-permission-role
  apiGroup: rbac.authorization.k8s.io
```

没有看错，我们使用的是「RoleBinding」而不是「ClusterRolebinding」来完成权限绑定。前文提到，「RoleBinding」是对某个「namespace」进行的权限绑定，而「ClusterRolebinding」是对整个集群做权限绑定，可以在「RoleBinding」时可以通过「roleRef」引用「ClusterRolebinding」，从而将集群的限制策略转为对「namespace」的权限绑定

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-3.png)

第五步：使用kubectl apply描述资源对象，就能向「userA」、「userB」赋予了两个不同「namespace」的Pod完全执行权限，过程如下：

```yaml
[root@k8s-master clusterrole]# kubectl apply -f cluster_pod_all_permission_role.yaml 
clusterrole.rbac.authorization.k8s.io/cluster-pod-all-permission-role created

[root@k8s-master clusterrole]# kubectl apply -f user_pod_rolebind.yaml 
rolebinding.rbac.authorization.k8s.io/tenanta-pod-all-permission-role-binding unchanged
rolebinding.rbac.authorization.k8s.io/tenantb-pod-all-permission-role-binding created
```

最后：我们来验证一下两个用户是否只能在当前租户空间（namespace）中操作Pod容器。如下图所示，k8s-node1使用userA作为用户账户，k8s-node2使用userB作为用户账户，它们仅能操作自身所在的namespace，除此之外无法访问任何namespace

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-4.png)

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-5.png)

## 实践场景2-使用ServiceAccount

在真实的渗透场景中，攻击者大多是通过Web网站拿到了某台容器的控制权限。在Kubernetes集群中，每台容器在启动时会被注入default权限的「ServiceToken」，位置在/var/run/secrets/kubernetes.io/serviceaccount，它是「ServiceAccount」（后文简称SA）的凭证

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-6.png)

为了展示较大权限的SA都能做哪些事情，现在我们在「tanent-a」命名空间下创建一个Thinkphp Web Service，对外暴露「30080」端口。其Pod容器使用的SA定义为「phpsa」，并且「phpsa」具有对当前「tanent-a」命名空间下Pod完全执行权限。

### 创建Service

第一步创建phpsa，并且赋予其tanent-a命名空间下对Pod容器完全执行权限

```yaml
#phpsa.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: phpsa
  namespace: tenant-a

---
apiVersion: rbac.authorization.k8s.io/v1  
kind: RoleBinding
metadata:
  name: phpsa-role-binding
  namespace: tenant-a
subjects:
- kind: ServiceAccount
  name: phpsa
  namespace: tenant-a
roleRef:
  kind: ClusterRole
  name: cluster-pod-all-permission-role
  apiGroup: rbac.authorization.k8s.io
```

第二步，通过如下资源描述文件创建漏洞环境的「Deployment」，将其暴露为「Service」服务。指定Pod容器默认注入的SA账户为「phpsa」

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: thinkphp5023-rce
  namespace: tenant-a
  labels:
    app: thinkphp5023-rce
spec:
  replicas: 2
  selector:
    matchLabels: # 跟template.metadata.labels一致
      app: thinkphp5023-rce
  template:
    metadata:
      labels:
        app: thinkphp5023-rce
    spec:
      containers:
      - name: thinkphp5023-rce-container
        image: vulhub/thinkphp:5.0.23
        ports:
        - containerPort: 80
          name: thinkphp-port
      serviceAccount: phpsa

---
apiVersion: v1
kind: Service
metadata:
  name: thinkphp5023-vulnerable-service
  namespace: tenant-a
spec:
  type: NodePort
  selector: # 更Deployment中的selector一致
    app: thinkphp5023-rce
  ports:
      # By default and for convenience, the 「targetPort」 is set to the same value as the 「port」 field.
    - port: 80
      name: thinkphp-port
      # Optional field
      # By default and for convenience, the Kubernetes control plane will allocate a port from a range (default: 30000-32767)
      nodePort: 30081
```

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-7.png)

到这里，一个具有RCE漏洞的thinkphp5.0.23版本就搭建完毕了，攻击者可以通过[thinkphp5.xRCE](https://github.com/oneoy/thinkphp-RCE-POC)漏洞建立「reverse shell」或上传「webshell」

### 后渗透利用

假设我们已经拿到「thinkphp」服务的容器权限，那么在后续的实战中，攻击者大多通过「cdk」等工具枚举当前SA账户「phpsa」都具有哪些权限

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-8.png)
但「cdk」做的事情比较有限，如下图「cdk」代码段所示，它通过访问「api/v1/namespaces」端点来断言自己是否拥有「list namespaces」权限，但却没有甄别当前SA账户处于哪个「namespace」下。
![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-9.png)
由于当前容器的服务账号为「phpsa」，具备「cluster-pod-all-permission-role」权限，理论上拥有「tenant-a」命名空间下Pod容器完全执行权限，如果仅用「cdk」当脚本小子，无疑浪费大好的攻击机会。

但话说回来，攻击者在此面临两个问题：
1. 盲视野攻击的状态下我们怎么能知道当前SA可以操作哪些命名空间呢？
2. 如何确定SA账户所在的命名空间呢？

对于第一个问题，笔者暂时没有找到很好的解决方案。而第二个问题有一种取巧的解决方法：当我们尝试去访问「api server」中任何越权的操作端点时，「api server」会返回「serviceaccount:x:y cannot list resource」错误，此时x代表当前SA账户所在的「namespace」，y就代表当前SA账户的用户名

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-10.png)
提取当前SA账户的「namespace」所属为「tenant-a」，接着就能列出命名空间「tenant-a」中的所有容器，也能进行后续的渗透操作

```bash
curl --cacert ./ca.crt --header "Authorization: Bearer $(cat ./token)" -X GET https://kubernetes.default.svc/api/v1/namespaces/tenant-a/pods
```

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2023/06/20/untitled-11.png)

# 写在最后
本文对理想条件下的「Kubernetes」授权进行了部分探究，但笔者比较好奇的是，业务态较广的云上业务，服务账号的授权行为不可能做到如此细粒度。那么有没有更快、更安全的做法将user group、namespace、准入控制玩出花活儿，从而让授权过程扁平化一些？先埋一个坑，等笔者有时间再探究一下