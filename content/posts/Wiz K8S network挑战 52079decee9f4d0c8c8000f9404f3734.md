---
author: HappyDog
title: Wiz-K8S-LAN-PARTY题解及思考
date: 2024-03-20
tags:
  - CloudNative
  - Kubernetes
categories:
  - CTF
---
# Wiz K8S network挑战

# TL;DR

此次挑战围绕Kubernetes网络服务展开，一共有5个题目。出题人在题目容器内提供了dnscan工具，dnscan能够针对给出的CIDR地址进行存活性探测，并根据IP地址反查其在集群中的域名地址。注意 ，每道题目都需要使用dnscan来确定本题开放的网络服务。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled.png)

# Challenge1

提示需要找到当前集群中存在的Web Service服务。在K8S集群中，Pod容器的「环境变量」包含了K8S的kube-apiserver通信地址，因此使用dnscan指定此类地址的B段扫描，能够得到集群存在的其他svc服务（如下图），在访问10.100.136.254的HTTP服务后拿到flag。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-1.png)

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-2.png)

这里再拓展一点关于网格服务（Service Mesh）的「坑」，但和题目本身无关。当前题目环境所在的K8S集群使用istio作为Service Mesh，用来转发Pod出口、入口的网络流量。在做题过程中发现，在使用nmap对10.100.136.254容器进行端口扫描，单从结果上看，这个IP地址所在容器开放了TCP全端口。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-3.png)

这种错误的结果在Kubernetes Service Mesh场景很常见，也是信息收集过程中的坑点：TCP端口的假阳性。[Kubernetes Internal Service Discovery](https://thegreycorner.com/2023/12/13/kubernetes-internal-service-discovery.html#kubernetes-dns-to-the-partial-rescue)这篇文章中，作者指出造成此现象的原因在与：

> 某些服务网格（例如 Istio）通过拦截某些 Pod 和服务的流量来工作，以提供功能更丰富的流量路由。在这种情况下，网格组件将为其配置范围内的所有有效端口和所有有效 IP 地址完成 TCP 三向握手，然后仅当存在到 pod 或服务的已配置服务网格路由时，才在后端转发连接。即使在关联的 IP 地址和/或端口上没有实际监听任何内容，这也会导致 TCP 端口看起来是打开的。当发生这种情况时，使用 TCP 握手来确定主机是否处于活动状态或端口是否打开的端口扫描程序将给出非常不准确的结果。在这些情况下，您只能依赖应用程序级别的响应返回，然后才能判断所谓的侦听 TCP 服务器是否确实背后有某些东西。
> 

因此，通过「TCP握手」情况来判断端口状态，并不适用存在K8S Service Mesh的场景中，那么常见的nmap和fscan工具都是不可取的。作者实现了一个简易版本的端口[扫描脚本](https://raw.githubusercontent.com/stephenbradshaw/pentesting_stuff/master/utilities/appportscan.py)：先建立TCP连接，使用socket发送捏造的TCP探针，根据是否有响应来判断端口的开放情况。当然这个脚本还是有点玩具性质，只对6379（redis）进行了处理而其他端口的探针一律捏造为HTTP请求。

# Challenge2

依然使用dnscan发现svc地址：10.100.171.123 -> reporting-service.k8s-lan-party.svc.cluster.local.

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-4.png)

同时，容器环境给了cap_net_admin，这允许我们通过tcpdump导出容器的虚拟网卡流量

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-5.png)

题目描述告知，当前Pod容器启动时存在[Sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)，且让我们借助Sidecar获取敏感数据。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-6.png)

请求reporting-service后的HTTP结果如下图，表明当前集群使用istio-envoy作为sidecar

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-7.png)

istio-envoy是一个proxy层面的sidecar。istio envoy的架构参考如下图，简单理解就是envoy作为Pod Proxy，伴随每个Pod启动。Pod中容器的所有出、入口流量都会流经instio-envoy这个proxy sidecar。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-8.png)

当在题目环境中执行netstat -all查看通信情况时，发现当前容器和reporting-service服务建立了大量http连接，那这个reporting-service服务很可能就是容器用到的proxy sidecar。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-9.png)

分析容器和reporting-service通信的流量即可，使用tcpdump抓取发往reporting-service的所有流量后，在某个HTTP POST请求中找到flag值

# Chall3

使用mount信息得知当前容器挂载了EFS文件系统，同时capsh信息依然保有cap_net_admin权限

```jsx
fs-0779524599b7d5e7e.efs.us-west-1.amazonaws.com:/ on /efs type nfs4 (ro,relatime,vers=4.1,rsize=1048576,wsize=1048576,namlen=255,hard,noresvport,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=192.168.23.121,local_lock=none,addr=192.168.124.98)
```

通过mount挂载的EFS文件目录中有flag.txt文件，但当前player用户不具备读权限

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-10.png)

EFS全称为Amazon Elastic File System，是用来给AWS EC2提供弹性存储空间的，EFS基于NFSv4.1 和 NFSv4.0协议实现，EFS客户端可以通过与EFS服务器端在2049端口的通信进行挂载操作。然而，当前EC2主机能否用mount命令挂载EFS，取决于AWS控制台中定义的「VPC网络控制安全组」是否设置了EC2 IP的allow access权限。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-11.png)

除了访问控制以外，还需要关注权限控制。AWS在[EFS文件系统的权限控制描述](https://docs.aws.amazon.com/zh_cn/efs/latest/ug/accessing-fs-nfs-permissions.html)中指明，EFS文件系统对于「文件权限」的判定基于Unix系统的用户标识符。这就意味着，uid=0的用户就是当前EFS文件系统的根用户，即最高权限用户。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-12.png)

结合这两点，读取flag.txt文件需要满足的条件：

- 当前节点的网络能够挂载EFS
- 当前节点的账号必须满足uid=0，从而读取flag.txt

这样便很容易想到将EFS Server的2049端口流量转发给自己的VPS，再使用VPS中的高权限用户挂载EFS，以高权限用户的身份读取flag.txt

# Chall4

第五题给了istio proxy的流量拦截规则如下。就是说在添加AuthorizationPolicy后，k8s-lan-party命名空间下的所有容器，过POST、GET请求访问flag容器HTTP服务的行为都会被istio拒绝。

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: istio-get-flag
  namespace: k8s-lan-party
spec:
  action: DENY
  selector:
    matchLabels:
      app: "{flag-pod-name}"
  rules:
  - from:
    - source:
        namespaces: ["k8s-lan-party"]
    to:
    - operation:
        methods: ["POST", "GET"]
```

依然先通过dnscan拿到flag容器地址：10.100.224.159 ，而后观察容器权限为root，且capbility是有cap_setgid,cap_setuid

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-13.png)

向10.100.224.159发起HTTP请求被拒绝，这是符合AuthorizationPolicy的预期。同时笔者测试DELETE、UPDATE、HEAD等请求也被拒绝，应该是Web服务没实现这些标准。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-14.png)

在istio的github issue中，有一个至今都没有解决的bug：‣ 。issue表明istio是以UID为1337的用户权限启动的，所以istio envoy不会检查来自UID为1337用户的出口流量

因此，我们只需要切换到istio自有的用户访问10.100.224.159即可。凑巧的是，笔者在做这题的时候还没有看到这个issue，只是「猜测」istio用户会不会在istio envoy的信任列表中，没想到歪打正着。

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-15.png)

不过单从利用方式来讲，让我想起前不久很像的容器逃逸手段：[一个未公开的容器逃逸方式
](https://www.anquanke.com/post/id/290540) 

# Chall5

题目给了kyverno的准入规则如下。kyverno作为Kubernetes支持的自定义准入控制器，主要用来验证和限制接入Kubernetes Cluster的资源，下面Policy的意思就是在sensitive-ns命名空间下建立新的Pod时，会自动地向Pod容器中注入flag环境变量。

```jsx
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: apply-flag-to-env
  namespace: sensitive-ns
spec:
  rules:
    - name: inject-env-vars
      match:
        resources:
          kinds:
            - Pod
      mutate:
        patchStrategicMerge:
          spec:
            containers:
              - name: "*"
                env:
                  - name: FLAG
                    value: "{flag}"
```

kyverno默认会开放一些服务，题目的网络环境直通这些服务。其中15001端口是kyverno的控制器，也就是AdmissionWebhook Server服务本身。一般来说，AdmissionWebhook Server在Kubernetes集群的准入控制原则中有Valiteda、Mutata、Generate、Verify Images这四类操作。这里讲一下题目涉及到的mutate操作流程：

1. **请求截获**：当一个请求（如创建、更新 Kubernetes 资源）发送到 API 服务器时，它首先被 Mutating Webhook 拦截。
2. **调用 Webhook**：API 服务器将请求转发给配置的 Mutating AdmissionWebhook Server。
3. **执行修改**：AdmissionWebhook Server 服务检查请求内容，并可以对Kubernetes资源对象进行修改。例如，它可以添加、删除或更新对象的某些字段。这允许在对象最终持久化之前实现自定义的修改逻辑。
4. **返回修改**：修改后的对象随着 Webhook 的响应返回给 API 服务器。
5. **持久化对象**：如果请求被多个 Mutating Webhooks 拦截，则按配置的顺序依次调用它们。所有 Mutating Webhooks 处理完毕后，修改后的对象被持久化存储。

到这里就不难理解kyverno是如何把flag塞进Pod容器了：通过「mutate操作」修改Pod容器的workload描述，随后再向kube-apiserver发起请求，根据修改后的workload描述建立Pod容器。整个过程相当于对「Pod Workload 描述文件」的spec.containers.env字段增加了env内容，具体可以参考kyverno文档中对拦截过程的描述

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-16.png)

比较离谱的是，通过helm安装的kyverno模式没有配置双向TLS，是可以直接通过容器的网络环境访问kyverno svc 15001端口的https rest api。于是解题思路就比较明确了：我们与AdmissionWebhook Server的mutate rest api接口交互，构造符合条件的准入请求，迫使AdmissionWebhook Server返回给我们mutate之后的Pod Workload描述，其中就包含了flag值，具体来说：

1. 给kyverno的Admission controller发送AdmissionReview请求，填充AdmissionReview.request字段，使其满足Policy。
2. Admission controller在对这样的AdmissionReview请求进行mutate后，填充env字段（flag）到AdmissionReview.response返回给用户。
3. 用户拿到http response后，解码AdmissionReview.response字段内容即可。

捏造完整的AdminissionReview请求如下：

```jsx
curl -X POST https://kyverno-svc.kyverno.svc.cluster.local/mutate -k -H "Content-Type: application/json" -d '{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "1234sdsa5-67890-abcdef",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "requestKind":{
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "requestResource":{
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "name": "CREATE",
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "namespace": "sensitive-ns",
    "operation": "CREATE",
    "userInfo": {
      "username": "kubernetes-admin",
      "uid": "1a2b3c4d5e",
      "groups": [
        "system:masters"
      ]
    },
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "example-pod",
        "namespace": "sensitive-ns"
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:latest"
          }
        ]
      }
    },
    "oldObject": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "example-pod",
        "namespace": "sensitive-ns"
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:latest"
          }
        ]
      }
    }
  }
}'

```

![Untitled](https://blog-1258539784.cos.ap-beijing.myqcloud.com/2024/03/25/untitled-17.png)
