/* sip-frontend - a simple sip balancer and stateless proxy for sip clusters. 

    Copyright (C) 2013-2014 Iñaki Cívico Campos.

    This file is part of sip-frontend.

    sip-frontend is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sip-frontend is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sip-frontend. If not, see <http://www.gnu.org/licenses/>.*/
    	
package com.iccapps.sip.frontend;

import gov.nist.javax.sip.header.Route;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.ListIterator;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TooManyListenersException;

import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.InvalidArgumentException;
import javax.sip.ListeningPoint;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.ServerTransaction;
import javax.sip.SipException;
import javax.sip.SipFactory;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.TimeoutEvent;
import javax.sip.TransactionAlreadyExistsException;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.TransactionUnavailableException;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.Header;
import javax.sip.header.HeaderFactory;
import javax.sip.header.RecordRouteHeader;
import javax.sip.header.RouteHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class Frontend implements SipListener {
	
	public static final String BRANCH_MAGIC_COOKIE = "z9hG4bK";
	
	private static Logger logger = Logger.getLogger(Frontend.class);
	private static Frontend instance;
	private static Properties config;
	
	protected Random rnd = new Random(System.currentTimeMillis());
	private SipStack sipStack;
	private SipFactory sipFactory;
	protected AddressFactory addressFactory;
	protected HeaderFactory headerFactory;
	protected MessageFactory messageFactory;
	protected SipProvider sipProvider;
	protected ListeningPoint udp;
	protected Map<String, NodeInfo> activeNodes = new HashMap<String, NodeInfo>();
	protected Map<String, Affinity> affinities = new HashMap<String, Affinity>();
	protected String lastNodeSelected;
	protected Timer timer = new Timer();
	
	static {
		config = new Properties();
		try {
			config.load(new FileInputStream(new File("frontend.properties")));
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		PropertyConfigurator.configure("log4j.properties");
	}
	
	private class Affinity {
		
		private String callid;
		private String nodeid;
		private TimerTask timeout;
		
		public Affinity(String c, String n) {
			callid = c;
			nodeid = n;
			refresh();
		}
		
		public void refresh() {
			if (timeout != null) timeout.cancel();
			
			timeout = new TimerTask() {
				@Override
				public void run() {
					affinities.remove(callid);
					logger.info("Evicted affinity " + callid);
				}
			};
			timer.schedule(timeout, 15000);
		}

		public String getCallid() {
			return callid;
		}
		
		public String getNodeid() {
			return nodeid;
		}

		public void setNodeid(String nodeid) {
			this.nodeid = nodeid;
		}
	}
	
	private class NodeInfo {
		private String uri;
		private String host;
		private int port;
		private TimerTask timeout;
		
		public NodeInfo() {
			refresh();
		}
		
		public void refresh() {
			if (timeout != null) timeout.cancel();
			timeout = new TimerTask() {
				@Override
				public void run() {
					synchronized (activeNodes) {
						activeNodes.remove(uri);
						logger.info("Evicted node " + uri + ", node list length: " + activeNodes.size());
					}
				}
			};
			timer.schedule(timeout, 2000);
		}
		
		public String getUri() {
			return uri;
		}
		public void setUri(String uri) {
			this.uri = uri;
		}
		public String getHost() {
			return host;
		}
		public void setHost(String host) {
			this.host = host;
		}
		public int getPort() {
			return port;
		}
		public void setPort(int port) {
			this.port = port;
		}
	}
	public synchronized static Frontend getInstance() {
		if (instance == null)
			instance = new Frontend();
		
		return instance;
	}
	
	private Frontend() { }
	
	public void start() throws FileNotFoundException, IOException, NumberFormatException, 
								InvalidArgumentException, TooManyListenersException, SipException, ParseException {
		
		logger.info("Starting sip frontend");
		
		sipFactory = SipFactory.getInstance();
		sipFactory.setPathName("gov.nist");
		
		Properties properties = new Properties();
		properties.setProperty("javax.sip.STACK_NAME","SIP Cluster Frontend");
		properties.setProperty("javax.sip.AUTOMATIC_DIALOG_SUPPORT", "off");
		//properties.load(new FileInputStream(new File("jsip.properties")));
		
		sipStack = sipFactory.createSipStack(properties);
		headerFactory = sipFactory.createHeaderFactory();
		addressFactory = sipFactory.createAddressFactory();
		messageFactory = sipFactory.createMessageFactory();
		
		
		String port = config.getProperty("frontend.port", "5060");
		String ip = config.getProperty("frontend.ip", "127.0.0.1");
		
		udp = sipStack.createListeningPoint(ip, Integer.parseInt(port), "udp");
		sipProvider = sipStack.createSipProvider(udp);
		sipProvider.addSipListener(this);
		sipStack.start();
	}
	
	public void stop() {
		logger.info("Stopping sip endpoint");
		if (sipProvider != null)
			sipProvider.removeSipListener(this);
		
		if (sipStack != null)
			sipStack.stop();
		
		sipStack = null;
	}
	
	public SipStack getSipStack() {
		return sipStack;
	}

	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	public HeaderFactory getHeaderFactory() {
		return headerFactory;
	}

	public MessageFactory getMessageFactory() {
		return messageFactory;
	}

	public SipProvider getSipProvider() {
		return sipProvider;
	}	

	public static void main( String[] args ) throws InterruptedException, NumberFormatException, FileNotFoundException, IOException, InvalidArgumentException, TooManyListenersException, SipException, ParseException {
        PropertyConfigurator.configure(new FileInputStream(new File("log4j.properties")));
		Frontend b = Frontend.getInstance();
        b.start();
        while(System.in.read() != 'q') Thread.sleep(200);
        
        b.stop();
        System.exit(0);
    }

	public void processDialogTerminated(DialogTerminatedEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	public void processIOException(IOExceptionEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	public void processRequest(RequestEvent ev) {
		Request req = ev.getRequest();
		//logger.debug("Received request " + req);
		
		ServerTransaction st = ev.getServerTransaction(); 
		if ( st != null ) {
			logger.warn("Received request with server transaction " + req);
			
		} else {
			if (isInDialog(req)) {
				// forward in-dialog requests
				logger.debug("Received in-dialog request " + req);
				forwardRequest(req);
				
			} else  {
				// request out of dialog
				if (req.getMethod().equals(Request.OPTIONS)) {
					Header keepalive = req.getHeader("X-Balancer");
					if (keepalive != null) {
						if(keepalive.toString().equals("X-Balancer: keepalive\r\n")) {
							processKeepAlive(req);
							
						} else { 
							 sendInternalServerError(req, "Invalid x-balancer header");
						}
					} else
						forwardRequest(req);
					
				} else {
					forwardRequest(req);
				}
			}
		}
	}

	@SuppressWarnings("rawtypes")
	public void processResponse(ResponseEvent ev) {
		Response res = ev.getResponse();
		
		// process response statelessly
		ListIterator viaList = res.getHeaders(ViaHeader.NAME);
        if (viaList != null && viaList.hasNext())
        {
            ViaHeader viaHeader = (ViaHeader) viaList.next();
            String viaHost = viaHeader.getHost();
            int viaPort = viaHeader.getPort();
            if (viaPort == -1) viaPort = 5060;

            if ( udp.getIPAddress().equals(viaHost) && viaPort == udp.getPort() )
            {
                if (logger.isTraceEnabled())
                    logger.trace("Top Via header matches proxy. Removing first Via header.");

                res.removeFirst(ViaHeader.NAME);

                viaList = res.getHeaders(ViaHeader.NAME);
                if (viaList.hasNext())
                {
                    try {
						sipProvider.sendResponse(res);
						
						if (logger.isDebugEnabled())
	                        logger.debug("Response forwarded statelessly.");

	                    if (logger.isTraceEnabled())
	                        logger.trace("\n"+res);
	                    
					} catch (SipException e) {
						e.printStackTrace();
					}
                } else {
                	logger.warn("No more vias in response!!");
                }
            }
        }
        else if (logger.isDebugEnabled())
            logger.debug("Via address doesn't match proxy or no Via headers left. Response is dropped.");
		
	}

	public void processTimeout(TimeoutEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	public void processTransactionTerminated(TransactionTerminatedEvent arg0) {
		// TODO Auto-generated method stub
		
	}
	
	private void forwardRequest(Request req) {
		logger.debug("Forwarding request " + req);
		
		ViaHeader via = (ViaHeader)req.getHeader(ViaHeader.NAME);
		
		if (isInitial(req)) {
			NodeInfo node = findNode(via.getHost(), via.getPort());
			if (node != null) {
				forwardOutboundInitial(req);
			} else {
				forwardInboundInitial(req);
			}
			
		} else {
			// find or create affinity
			NodeInfo node = processAffinityInDialog(req);
			/*Affinity a = affinities.get(callid);
			if (a != null) {
				a.refresh();
				node = activeNodes.get(a.getNodeid());
				if (node == null) {
					logger.error("Node not available");
					sendInternalServerError(req, "Node not available");	
					return;
				}
			} else {
				logger.error("Affinity not found");
				sendInternalServerError(req, "Affinity not found");
				return;
			}*/
			if (node == null) {
				logger.error("Node or affinity for request not found");
				//sendInternalServerError(req, "Affinity not found");
				// do nothing, wait for retries
				return;
			}
			
			if (via.getHost().equals(node.getHost()) && via.getPort() == node.getPort()) {
				forwardOutboundIndialog(req);
			} else {
				forwardInboundIndialog(req, node);
			}
		}
	}
	
	/**
	 * Forwards initial request originated outside the cluster
	 * @param req
	 */
	private void forwardInboundInitial(Request req) {
		if(req.getMethod().equals(Request.INVITE) || 
				req.getMethod().equals(Request.CANCEL) ||
				req.getMethod().equals(Request.REGISTER) ||
				req.getMethod().equals(Request.OPTIONS)) {
			
			String callid = ((CallIdHeader)req.getHeader(CallIdHeader.NAME)).getCallId();
			
			// select node
			NodeInfo node = selectActiveNode();
			if (node != null) {
				logger.debug("Forward initial request to " + node.getUri());
				
				Affinity a = new Affinity(callid, node.getUri());
				affinities.put(callid, a);
				// clone request
				Request clonedReq = (Request) req.clone();
				
				try {
					// remove routes
					clonedReq.removeHeader(Route.NAME);
					
					// add record-route
					SipURI sipURI = addressFactory.createSipURI(null, udp.getIPAddress());
					sipURI.setPort(udp.getPort());
					sipURI.setLrParam();
			        Address address = addressFactory.createAddress(null, sipURI);
			        RecordRouteHeader recordRouteHeader = headerFactory.createRecordRouteHeader(address);
			        clonedReq.addFirst(recordRouteHeader);
			        
					// set requestUri to node
			        clonedReq.setRequestURI(addressFactory.createURI(node.getUri()));
			        
			        // forward
			        sendRequest(clonedReq);
						
				} catch (ParseException e) {
					e.printStackTrace();
					sendInternalServerError(req, "Error forwarding request");
					
				} catch (NullPointerException e) {
					e.printStackTrace();
					sendInternalServerError(req, "Error forwarding request");
					
				} catch (SipException e) {
					e.printStackTrace();
					sendInternalServerError(req, "Error forwarding request");
				}
		        
			} else {
				// no node available, do nothing
				logger.debug("No node available for request");
			}
		} else {
			logger.debug("Initial request method not allowed " + req.getMethod());
			sendInternalServerError(req, "Initial request method not allowed");
		}
	}
	
	/**
	 * Forwards initial request originated inside the cluster
	 * @param req
	 */
	private void forwardOutboundInitial(Request req) {
		String callid = ((CallIdHeader)req.getHeader(CallIdHeader.NAME)).getCallId();
		logger.debug("Forwarding outbound " + callid);
	
		// select node
		NodeInfo node = selectActiveNode();
		if (node != null) {
			logger.debug("Forward initial request to " + node.getUri());
			
			// create affinity
			Affinity a = new Affinity(callid, node.getUri());
			affinities.put(callid, a);
			// 16.6 Request Forwarding
			// 1.  Make a copy of the received request
			Request clonedReq = (Request) req.clone();
			// 2.  Update the Request-URI
			@SuppressWarnings("rawtypes")
			ListIterator routes = clonedReq.getHeaders(RouteHeader.NAME);
			if (routes != null && routes.hasNext()) {
				RouteHeader route = (RouteHeader)routes.next();
				if ( ((SipURI)route.getAddress().getURI()).hasLrParam()) {
					/* If the route set is not empty, and the first URI in the route set
					   contains the lr parameter (see Section 19.1.1), the UAC MUST place
					   the remote target URI into the Request-URI and MUST include a Route
					   header field containing the route set values in order, including all
					   parameters.*/
					clonedReq.removeFirst(RouteHeader.NAME);
					
				} else {
					/* If the route set is not empty, and its first URI does not contain the
					   lr parameter, the UAC MUST place the first URI from the route set
					   into the Request-URI, stripping any parameters that are not allowed
					   in a Request-URI.  The UAC MUST add a Route header field containing
					   the remainder of the route set values in order, including all
					   parameters.  The UAC MUST then place the remote target URI into the
					   Route header field as the last value.*/
				}
				
			} else {
				/* If the route set is empty, the UAC MUST place the remote target URI
				   into the Request-URI.  The UAC MUST NOT add a Route header field to
				   the request.*/
			}
			
			// 3.  Update the Max-Forwards header field
			
			// 4.  Optionally add a Record-route header field value
			SipURI sipURI;
			try {
				sipURI = addressFactory.createSipURI(null, udp.getIPAddress());
				sipURI.setPort(udp.getPort());
				sipURI.setLrParam();
		        Address address = addressFactory.createAddress(null, sipURI);
		        RecordRouteHeader recordRouteHeader = headerFactory.createRecordRouteHeader(address);
		        clonedReq.addFirst(recordRouteHeader);
		        
			} catch (ParseException e) {
				e.printStackTrace();
				sendInternalServerError(req, "Could not create record-route");
			} catch (NullPointerException e) {
				e.printStackTrace();
				sendInternalServerError(req, "Could not create record-route");
			} catch (SipException e) {
				e.printStackTrace();
				sendInternalServerError(req, "Could not create record-route");
			}
			// 5.  Optionally add additional header fields
			// 6.  Postprocess routing information
	        // 7.  Determine the next-hop address, port, and transport
			sendRequest(clonedReq);
			
		} else {
			logger.error("No available node");
			sendInternalServerError(req, "No available node");
		}
	}
	
	/**
	 * Forwards request originated outside the cluster
	 * @param req
	 * @param node
	 */
	private void forwardInboundIndialog(Request req, NodeInfo node) {
		// forward into cluster
		String callid = ((CallIdHeader)req.getHeader(CallIdHeader.NAME)).getCallId();
		logger.debug("Forwarding inbound " + callid);
		try {
			// clone request
			Request clonedReq = (Request) req.clone();
			
			clonedReq.setRequestURI(addressFactory.createURI(node.getUri()));
			clonedReq.removeHeader(RouteHeader.NAME);
			
			sendRequest(clonedReq);
				
		} catch (ParseException e) {
			e.printStackTrace();
			sendInternalServerError(req, "Error forwarding request");
		}
	}
	
	/**
	 * Forwards request originated inside the cluster
	 * @param req
	 */
	private void forwardOutboundIndialog(Request req) {
		String callid = ((CallIdHeader)req.getHeader(CallIdHeader.NAME)).getCallId();
		logger.debug("Forwarding outbound " + callid);
		
		// 16.6 Request Forwarding
		// 1.  Make a copy of the received request
		Request clonedReq = (Request) req.clone();
		// 2.  Update the Request-URI
		@SuppressWarnings("rawtypes")
		ListIterator routes = clonedReq.getHeaders(RouteHeader.NAME);
		if (routes != null && routes.hasNext()) {
			RouteHeader route = (RouteHeader)routes.next();
			if ( ((SipURI)route.getAddress().getURI()).hasLrParam()) {
				/* If the route set is not empty, and the first URI in the route set
				   contains the lr parameter (see Section 19.1.1), the UAC MUST place
				   the remote target URI into the Request-URI and MUST include a Route
				   header field containing the route set values in order, including all
				   parameters.*/
				clonedReq.removeFirst(RouteHeader.NAME);
				
			} else {
				/* If the route set is not empty, and its first URI does not contain the
				   lr parameter, the UAC MUST place the first URI from the route set
				   into the Request-URI, stripping any parameters that are not allowed
				   in a Request-URI.  The UAC MUST add a Route header field containing
				   the remainder of the route set values in order, including all
				   parameters.  The UAC MUST then place the remote target URI into the
				   Route header field as the last value.*/
			}
			
		} else {
			/* If the route set is empty, the UAC MUST place the remote target URI
			   into the Request-URI.  The UAC MUST NOT add a Route header field to
			   the request.*/
		}
		
		// 3.  Update the Max-Forwards header field
		// 4.  Optionally add a Record-route header field value
		// 5.  Optionally add additional header fields
		// 6.  Postprocess routing information
        // 7.  Determine the next-hop address, port, and transport
		sendRequest(clonedReq);
	}
	
	/**
	 * Sends request. Creates Via header and sends through provider statelessly
	 * @param req
	 */
	private void sendRequest(Request req) {
		try
        {
			// 8.  Add a Via header field value
			/* 16.11 
				The requirement for unique branch IDs across space and time
	         applies to stateless proxies as well.  However, a stateless
	         proxy cannot simply use a random number generator to compute
	         the first component of the branch ID, as described in Section
	         16.6 bullet 8.  This is because retransmissions of a request
	         need to have the same value, and a stateless proxy cannot tell
	         a retransmission from the original request.  Therefore, the
	         component of the branch parameter that makes it unique MUST be
	         the same each time a retransmitted request is forwarded.  Thus
	         for a stateless proxy, the branch parameter MUST be computed as
	         a combinatoric function of message parameters which are
	         invariant on retransmission.

	         	The stateless proxy MAY use any technique it likes to guarantee
	         uniqueness of its branch IDs across transactions.  However, the
	         following procedure is RECOMMENDED.  The proxy examines the
	         branch ID in the topmost Via header field of the received
	         request.  If it begins with the magic cookie, the first
	         component of the branch ID of the outgoing request is computed
	         as a hash of the received branch ID.  Otherwise, the first
	         component of the branch ID is computed as a hash of the topmost
	         Via, the tag in the To header field, the tag in the From header
	         field, the Call-ID header field, the CSeq number (but not
	         method), and the Request-URI from the received request.  One of
	         these fields will always vary across two different
	         transactions. */
			
			String branchId = null/*SipUtils.generateBranchId()*/;
            ViaHeader topmostViaHeader = (ViaHeader) req.getHeader(ViaHeader.NAME);
            if (topmostViaHeader != null)
            {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                String branch = topmostViaHeader.getBranch();

                byte[] hash = null;
                
                if (branch.startsWith(BRANCH_MAGIC_COOKIE)) {
                	hash = messageDigest.digest(Integer.toString(branch.hashCode()).getBytes());
                	
                } else {
                	StringBuffer s = new StringBuffer();
                    s.append(topmostViaHeader.toString().trim());
                    s.append(((ToHeader) req.getHeader(ToHeader.NAME)).getTag());
                    s.append(((FromHeader) req.getHeader(FromHeader.NAME)).getTag());
                    s.append(((CallIdHeader) req.getHeader(CallIdHeader.NAME)).getCallId());
                    s.append(((CSeqHeader) req.getHeader(CSeqHeader.NAME)).getSeqNumber());
                    s.append(req.getRequestURI().toString().trim());

                    hash = messageDigest.digest(s.toString().getBytes());
                }
                // stringify
                branchId = bytesToHex(hash);
            }
            // create header
            ViaHeader viaHeader = headerFactory.createViaHeader(udp.getIPAddress(), udp.getPort(), "udp", branchId);
            req.addFirst(viaHeader);
            
        } catch(NoSuchAlgorithmException e) {
        	e.printStackTrace();
        	// TODO - 500
        } catch (ParseException e) {
			e.printStackTrace();
		} catch (InvalidArgumentException e) {
			e.printStackTrace();
		} catch (NullPointerException e) {
			e.printStackTrace();
		} catch (SipException e) {
			e.printStackTrace();
		}
		
		// 9.  Add a Content-Length header field if necessary
		// 10. Forward the new request
		try {
			sipProvider.sendRequest(req);
			logger.debug("Forwarded " + req.getMethod());
			
		} catch (SipException e) {
			e.printStackTrace();
		}
	}
	
	private boolean isInitial(Request req) {
		return !isInDialog(req);
	}
	
	/**
	 * Returns true if there is to tag
	 * @param req
	 * @return
	 */
	private boolean isInDialog(Request req) {
		ToHeader to = (ToHeader)req.getHeader(ToHeader.NAME);
		if (to != null) {
			if (to.getTag() != null) return true;
		}
		
		return false;
	}
	
	private NodeInfo selectActiveNode() {
		try {
			synchronized (activeNodes) {
				if (lastNodeSelected == null) {
					// get first
					for(NodeInfo node : activeNodes.values()) {
						lastNodeSelected = node.getUri();
						return node;
					}

				} else {
					boolean next = false;
					for (NodeInfo node : activeNodes.values()) {
						if (next) {
							lastNodeSelected = node.getUri();
							return node;
						}
						if (node.getUri().equals(lastNodeSelected)) {
							next = true;
						}
					}
					// get first
					for(NodeInfo node : activeNodes.values()) {
						lastNodeSelected = node.getUri();
						return node;
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		logger.debug("No active node available: " + activeNodes.size());
		return null;
	}
	
	private NodeInfo findNode(String host, int port) {
		synchronized (activeNodes) {
			for(NodeInfo n : activeNodes.values()) {
				if (n.getHost().equals(host) && n.getPort() == port)
					return n;
			}
		}
		return null;
	}
	
	/**
	 * Handles keepalive from cluster nodes and stores node info 
	 * @param req
	 */
	private void processKeepAlive(Request req) {
		// TODO - verify origin against a list of authorized nodes/IPs
		// ping from sip node
		Response res;
		try {
			res = messageFactory.createResponse(Response.OK, req);
			((ToHeader)res.getHeader(ToHeader.NAME)).setTag(""+rnd.nextLong());
			
			synchronized(activeNodes) {
				// add sip node
				ViaHeader via = (ViaHeader)req.getHeader(ViaHeader.NAME);
				String uri = "sip:"+via.getHost()+":"+via.getPort();
				NodeInfo node = activeNodes.get(uri);
				if (node != null) {
					node.refresh();
					
				} else {
					node = new NodeInfo();
					node.setUri(uri);
					node.setHost(via.getHost());
					node.setPort(via.getPort());
					activeNodes.put(node.getUri(), node);
					logger.info("SIP node added: " + uri);
				}
			}
			sipProvider.sendResponse(res);
			//logger.debug("Sent response: " + res.getStatusCode());
			
		} catch (ParseException e) {
			e.printStackTrace();
			sendInternalServerError(req, "Could not process keepalive request");
			
		} catch (TransactionAlreadyExistsException e) {
			e.printStackTrace();
			sendInternalServerError(req, "Could not process keepalive request");
			
		} catch (TransactionUnavailableException e) {
			e.printStackTrace();
			sendInternalServerError(req, "Could not process keepalive request");
			
		} catch (SipException e) {
			e.printStackTrace();
			sendInternalServerError(req, "Could not process keepalive request");
			
		}	
	}

	/**
	 * Checks or creates affinities. If request comes from cluster, it gets affinity o creates one 
	 * if it cannot be found. If request comes from external ua, it finds affinity and return node
	 * associated or returns null if affinity or node cannot be found.
	 * As a result, all outbound requests refresh or create a new affinity. In the case of balancer
	 * crash and restart, a simple request from cluster recreates all needed information. 
	 * @param req
	 * @return
	 */
	private NodeInfo processAffinityInDialog(Request req) {
		logger.debug("Affinity updating");
		NodeInfo node = null;
		try {
			// update affinity
			String callid = ((CallIdHeader)req.getHeader(CallIdHeader.NAME)).getCallId();
			ViaHeader via = (ViaHeader)req.getHeader(ViaHeader.NAME);
			String uri = "sip:"+via.getHost()+":"+via.getPort();
			Affinity a = affinities.get(callid);
			node = activeNodes.get(uri);
			if (a == null) {
				if (node != null) {
					// outbound request
					if (req.getMethod().equals(Request.OPTIONS)) {
						// restore affinity on OPTIONS
						a = new Affinity(callid, node.getUri());
						affinities.put(callid, a);
						logger.info("New affinity created:" + a.getCallid() + ", " + a.getNodeid());
						
					} else {
						logger.warn("Outbound request without affinity info: " + callid);
					}
					
				} else {
					// inbound request
					logger.debug("Inbound request " + uri + " without affinity");
					// -- wait for node handover and uac retry --
				}
			} else {
				if (node != null) {
					// outbound request, update node info
					a.setNodeid(node.getUri());
					a.refresh();
					logger.debug("Affinity updated:" + a.getCallid() + ", " + a.getNodeid());
					
				} else {
					// inbound request, get related node
					node = activeNodes.get(a.getNodeid());
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
			node = null;
		}
		
		return node;
	}

	private void sendInternalServerError(Request req, String message) {
		try {
			Response res = messageFactory.createResponse(Response.SERVER_INTERNAL_ERROR, req);
			res.setReasonPhrase(message);
			((ToHeader)res.getHeader(ToHeader.NAME)).setTag(""+rnd.nextLong());
			
			sipProvider.sendResponse(res);
			
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (TransactionAlreadyExistsException e) {
			e.printStackTrace();
		} catch (TransactionUnavailableException e) {
			e.printStackTrace();
		} catch (SipException e) {
			e.printStackTrace();
		} 
	}
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
