sip-frontend
============

Simple balancer and frontend for SIP clusters

This is a simple balancer for SIP. It works as a frontend for a SIP cluster, receiving all requests and 
forwarding them statelessly to nodes. A SIP node registers on frontend/balancer sending OPTIONS with a special 
header (X-Balancer: keepalive). A dialog keeps attached to a node, so all requests of a call are handled 
by the same sip node. SIP node can refresh affinity information sending a regular OPTION message.

In the case of a node failure, another node in the cluster can handover its calls and refresh affinity information
sending an OPTION message, so all following requests will be forwarded to the new node.

This program has been made for learning purposes and is shared with no guarantee. Please see license details.
