package br.ufpe.gprt.floodlight.transparentCache;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.gtp.AbstractGTP;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpMatcher implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private Map<Integer,DummyHTTPClient> connectedDummyClients;
//	private Map<IPv4Address,IGTPHeader> lastSequenceNumber;
	private Map<IPv4Address,Map<Integer, GTPTunnelContext>> tunnelContexts;
	private Map<IPv4Address,Map<Integer, GTPPayloadContext>> gtpPayloadContext;

	protected static Logger logger;

	@Override
	public String getName() {
		return "HttpMatcher";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		logger.warn("Packet In...");
//		if(true)
//			return Command.STOP;

		OFPacketIn pin = (OFPacketIn) msg;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (eth.getEtherType().equals(EthType.LLDP)) {
			return Command.CONTINUE;
		}

		if (eth.getEtherType().equals(EthType.ARP)) {
			if (eth.getDestinationMACAddress().isBroadcast()) {
				ARP arp = (ARP) eth.getPayload();
				logger.warn("Target address for ARP "
						+ arp.getTargetProtocolAddress().toString());
			}
			return Command.CONTINUE;
		}

		logger.warn("Lets test this Packet in... type= |"+eth.getEtherType() +"| ipv4 is =|"+Ethernet.TYPE_IPv4+"|");
		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();
			
			logger.warn("Packet ins IPV4 and protocol is "+ip.getProtocol());
			if (ip.getProtocol().equals(IpProtocol.UDP)) {
				UDP udp = (UDP) ip.getPayload();
				
				logger.warn("Packet in is UDP and has port S="+udp.getSourcePort()+" D="+udp.getDestinationPort());

				if (udp.getSourcePort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getSourcePort().equals(UDP.GTP_CONTROL_PORT)
						|| udp.getDestinationPort().equals(UDP.GTP_CLIENT_PORT)
						|| udp.getDestinationPort()
								.equals(UDP.GTP_CONTROL_PORT)) {
					AbstractGTP gtp = (AbstractGTP) udp.getPayload();
					
					logger.warn("GTP RECEIVED!");
					
					Map<Integer,GTPTunnelContext> specificIpContextsPerPort = null;
					GTPTunnelContext contextPerIpperPort = null;
					int udpSrcPort = udp.getSourcePort().getPort();
					if(this.tunnelContexts.containsKey(ip.getSourceAddress())){
						specificIpContextsPerPort = this.tunnelContexts.get(ip.getSourceAddress());
						
						if(specificIpContextsPerPort.containsKey(udpSrcPort)){
							contextPerIpperPort = specificIpContextsPerPort.get(udpSrcPort);
						} else {
							contextPerIpperPort = new GTPTunnelContext();
						}
					} else {
						specificIpContextsPerPort = new HashMap<Integer, GTPTunnelContext>();
						contextPerIpperPort = new GTPTunnelContext();
					}
					contextPerIpperPort.updateContext(eth);
					specificIpContextsPerPort.put(udpSrcPort, contextPerIpperPort);
					this.tunnelContexts.put(ip.getSourceAddress(), specificIpContextsPerPort);
					
					if (!gtp.isControlPacket()) {

						IPv4 gtpIp = (IPv4) gtp.getPayload();
						logger.warn("GTP NOT Control Packet Proto = "+gtpIp.getProtocol());

						if (gtpIp.getProtocol().equals(IpProtocol.TCP)) {

							TCP tcp = (TCP) gtpIp.getPayload();
							logger.warn("TCP on top of GTP detected! port = "+tcp.getDestinationPort());
							
							
							GTPPayloadContext payloadContext = null;
							Map<Integer,GTPPayloadContext> specificIpContextsOnGTPPerPort = null;
							int tcpSrcPort = tcp.getSourcePort().getPort();
							if(this.gtpPayloadContext.containsKey(gtpIp.getSourceAddress())){
								specificIpContextsOnGTPPerPort = this.gtpPayloadContext.get(gtpIp.getSourceAddress());
								
								if(specificIpContextsOnGTPPerPort.containsKey(tcpSrcPort)){
									payloadContext = specificIpContextsOnGTPPerPort.get(tcpSrcPort);
								} else {
									payloadContext = new GTPPayloadContext();
								}
							} else {
								specificIpContextsOnGTPPerPort = new HashMap<Integer, GTPPayloadContext>();
								payloadContext = new GTPPayloadContext();
							}
							payloadContext.setTunnelContext(contextPerIpperPort);
							payloadContext.updateContext(gtpIp, pin.getInPort(), sw);
							specificIpContextsOnGTPPerPort.put(tcpSrcPort, payloadContext);
							this.gtpPayloadContext.put(gtpIp.getSourceAddress(), specificIpContextsOnGTPPerPort);
							
							
							//BUG! TODO
							// destination port has to be 80 but destination address
							// has to be one of the known HTTP servers.
							if (tcp.getDestinationPort().equals(
									TransportPort.of(80))) {
								
								Data data = (Data) tcp.getPayload();
								byte[] bytes = data.getData();
								
								if(bytes.length > 0){

									String s = new String(bytes);
									System.out.println("TCP Payload was "+s);
									
									if(s.contains("GET") && s.contains("HTTP") && s.contains("mp4")){
										String host = "192.168.1.3";
										logger.warn("HTTP GET detected, forwarding it to "+host);
										
										int udpDstPort = udp.getDestinationPort().getPort();
										GTPTunnelContext ackGTPTunnel = null;
										if(this.tunnelContexts.containsKey(ip.getDestinationAddress())){
											
											Map<Integer, GTPTunnelContext> map = this.tunnelContexts.get(ip.getDestinationAddress());
											
											if(map.containsKey(udpDstPort)){
												ackGTPTunnel = map.get(udpDstPort);
											}
										}
										
										if(ackGTPTunnel == null){
											throw new RuntimeException("No context for this tunnel, trying to splice a new connection?");
										}
										
										
										GTPPayloadContext ackPayloadContext = null;
										int tcpDstPort = tcp.getDestinationPort().getPort();

										if(this.gtpPayloadContext.containsKey(gtpIp.getDestinationAddress())){
											Map<Integer, GTPPayloadContext> map = this.gtpPayloadContext.get(gtpIp.getDestinationAddress());
											
											if(map.containsKey(tcpDstPort)){
												ackPayloadContext = map.get(tcpDstPort);
											}
										}
										
										if(ackPayloadContext == null){
											throw new RuntimeException("No previous payload for this tunnel, trying to splice a new connection?");
										}
										
										IPv4 ackGTPIp = ackPayloadContext.getACK(bytes.length);
//										Ethernet ack = ackGTPTunnel.getPacketWithPayload(ackGTPIp);
										Ethernet ack = ackPayloadContext.getTunnelContext().getPacketWithPayload(ackGTPIp);
										
										createAndSendPacketOut(ackPayloadContext.getSw(), ack.serialize(), ackPayloadContext.getOFPort());

//										ACK -> seq
//										seq -> ACK

										//CHANGE THIS! TODO
										//THIS IS UGLY AS HELL!
										
										int selectedPort = tcp.getDestinationPort().getPort();
										IPv4Address selectedAddress = gtpIp.getDestinationAddress();
										
										boolean alreadyDownloadingThisData = this.checkDummyClients(selectedAddress, selectedPort);
										logger.warn("TESTING! Previous client for "+selectedAddress +" "+ selectedPort + " r="+alreadyDownloadingThisData);

										if(!alreadyDownloadingThisData){
											logger.warn("CONFIRMED! No previous client for "+selectedAddress +" "+ selectedPort);

//											DummyHTTPClient dummyClient = new DummyHTTPClient(host, 80, s, this, selectedAddress, selectedPort);
//											Thread t = new Thread(dummyClient);
//											t.start();
										}
										
										return Command.STOP;
									}
								}
							}
						}

						
					}

				}
			} if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				logger.warn("Intercepted TCP received outside of GTP. P="+tcp.getDestinationPort()+" A="+ip.getDestinationAddress());
				
				try {
			        Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			        for (NetworkInterface netint : Collections.list(nets)){
			        	Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
			        	
			            for (InetAddress inetAddress : Collections.list(inetAddresses)) {
						logger.warn("Checking address "+inetAddress);
						if(ip.getDestinationAddress().equals(IPv4Address.of(inetAddress))){
							logger.warn("IP OK, checking port "+tcp.getDestinationPort().getPort());

							if(this.connectedDummyClients.containsKey(tcp.getDestinationPort().getPort())){
								logger.warn("SUCESS! Dummy client found!");
								DummyHTTPClient dummyClient = this.connectedDummyClients.get(tcp.getDestinationPort().getPort());
								
								
								GTPPayloadContext httpPayloadContext = null;
								int tcpDstPort = dummyClient.getSourcePort();

								if(this.gtpPayloadContext.containsKey(dummyClient.getSourceAddress())){
									Map<Integer, GTPPayloadContext> map = this.gtpPayloadContext.get(dummyClient.getSourceAddress());
									
									if(map.containsKey(tcpDstPort)){
										httpPayloadContext = map.get(tcpDstPort);
									}
								}
								
								if(httpPayloadContext == null){
									throw new RuntimeException("No previous payload for this tunnel, trying to splice a new connection?");
								}
								
								
								
								
//								ClientTCPSplicingInfo splicingInfo = this.tunnelContexts.get(dummyClient.getSourceAddress()).get(dummyClient.getSourcePort());
								
								
								Data data = (Data) tcp.getPayload();
								byte[] bytes = data.getData();
								
								if(bytes.length > 0){
									String originalMessage = new String(bytes);
									bytes = originalMessage.replace("video", "vedio").getBytes();
									
//									Ethernet cachedEth = splicingInfo.getContext(bytes);
//									byte[] serializedData = cachedEth.serialize();
//									
//									createAndSendPacketOut(sw, serializedData);
									String s = new String(bytes);
									logger.warn("Size = "+ bytes.length + "\n"+s);
								}

//								Ethernet payloadGTPIp = httpPayloadContext.getTunneledPayloadOf(bytes);
//								Ethernet payloadContext = httpPayloadContext.getTunnelContext().getPacketWithPayload(payloadGTPIp);
								
//								IPv4 ackGTPIp = httpPayloadContext.getTunneledPayloadOf(bytes);
								IPv4 httpGTPed = httpPayloadContext.getTunneledPayloadOf(tcp);
								TCP httpTCPData = httpPayloadContext.getPayloadOf(tcp);

//								Ethernet ack = ackGTPTunnel.getPacketWithPayload(ackGTPIp);
//								Ethernet httpData = httpPayloadContext.getTunnelContext().getPacketWithPayload(ackGTPIp);
								
								Ethernet httpData = httpPayloadContext.getTunnelContext().getPacketWithPayload(httpGTPed);
								
								httpData.setPayload(httpTCPData);
								httpTCPData.setParent(httpData);

								
//								createAndSendPacketOut(httpPayloadContext.getSw(), httpData.serialize(), httpPayloadContext.getOFPort());
								
								createAndSendPacketOut(httpPayloadContext.getSw(), httpData.serialize(), OFPort.FLOOD);

								
								
								break;
							}
							
						}
					}
			        }
				} catch (SocketException e) {
					e.printStackTrace();
				}

			}
		}

		return Command.CONTINUE;
	}

	private boolean checkDummyClients(IPv4Address iPv4Address, int port) {
		Set<Integer> localPorts = this.connectedDummyClients.keySet();
		for (int localPort : localPorts) {
			DummyHTTPClient client = this.connectedDummyClients.get(localPort);
			
			System.out.println("Checking "+client.getSourceAddress() + "=="+iPv4Address);
			System.out.println("Checking "+client.getLocalPort() + "=="+port);

			if(client.getSourceAddress().equals(iPv4Address) && client.getSourcePort() == port){
				return true;
			}
		}
		return false;
	}

	private void createAndSendPacketOut(IOFSwitch sw, byte[] serializedData, OFPort outputPort) {
		OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
			    .setData(serializedData)
			    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(outputPort, 0xffFFffFF)))
			    .setInPort(OFPort.CONTROLLER)
			    .build();
			 
			sw.write(po);
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		this.connectedDummyClients = new HashMap<Integer, DummyHTTPClient>();
		this.tunnelContexts = new HashMap<IPv4Address, Map<Integer,GTPTunnelContext>>();
		this.gtpPayloadContext = new HashMap<IPv4Address, Map<Integer,GTPPayloadContext>>();
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);

		logger = LoggerFactory.getLogger(HttpMatcher.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

//		for (Class<? extends IFloodlightService> service : context
//				.getAllServices()) {
//			logger.warn("Name " + service.getSimpleName());
//		}
//
//		Map<OFType, List<IOFMessageListener>> map = floodlightProvider
//				.getListeners();
//		for (Map.Entry<OFType, List<IOFMessageListener>> entry : map.entrySet()) {
//			logger.warn("Key = " + entry.getKey() + ", Value = "
//					+ entry.getValue());
//		}
	}

	public void addConnectedDummyClient(int localPort, DummyHTTPClient dummyHTTPClient) {
		logger.warn("WARNING!! Adding a new client"+dummyHTTPClient.toString());

		this.connectedDummyClients.put(localPort, dummyHTTPClient);
	}

	public void delConnectedDummyClient(int localPort) {
		if(this.connectedDummyClients.containsKey(localPort)){
//			this.connectedDummyClients.remove(localPort);
		}
	}
}
