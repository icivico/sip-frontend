sip-frontend
============

Simple balancer and frontend for SIP clusters

This is a simple balancer for SIP. It works as a frontend for a SIP cluster, receiving all requests and forwarding them to nodes. SIP nodes registers on frontend sending OPTIONS with a special header. A dialog keeps attached to a node, so all requests of a call are handled by the same sip node. A node can refresh this affinity information with a simple OPTION.

In the case of a node failure, another node can handover a call and send an OPTION message, which will refresh affinity information. Then all subsequent requests will be forwarded to the new node.

This program has been made for learning purpouses and is shared with no guarantee. Please see license details.
