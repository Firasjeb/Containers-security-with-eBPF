# Containers security with ebPF

This project has been made during my internship at Orange Innovation, a french telecommunication company. 
This project is a proof of a concept to the issues related to the security and confidentality of datas exchanged between Virtual network function (VNF) that Orange deploys on its cloud to ensure 5G communications. 
The project uses eBPF as a tool to interpect and analyze traffic encrypted traffic between containers. This POOC shows that using eBPF and KTLS ( Kernel transport Layer Security) it is possible to observe the traffic in plain data even if it was encrypted using TLS, reflecting secuiryt issues.

https://netdevconf.info/1.2/papers/ktls.pdf
