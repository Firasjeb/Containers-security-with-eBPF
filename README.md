# Containers security with ebPF

This project has been made during my internship at Orange Innovation, a french telecommunication company.  

This project is a proof of a concept to the issues related to the security and confidentality of datas exchanged between Virtual network function (VNF) that Orange deploys on its cloud to ensure 5G communications.  

The project uses eBPF as a tool to interpect and analyze traffic encrypted traffic between containers. This POOC shows that using eBPF and KTLS ( Kernel transport Layer Security) it is possible to observe the traffic in plain data even if it was encrypted using TLS, reflecting security issues.\\
In this repo you will find a state of the art of the existing work related to this subject and a comparison between all the techniques by studying different metrics, as latency, speed and overhead introduced by the host OS.

https://netdevconf.info/1.2/papers/ktls.pdf
https://blog.px.dev/ebpf-openssl-tracing/
