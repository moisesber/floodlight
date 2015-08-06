package br.ufpe.gprt.floodlight.transparentCache;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
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
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpTransparentCache implements IFloodlightModule,
		IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private Map<Integer, DummyHTTPClient> connectedDummyClients;
	private Map<IPv4Address, Map<Integer, GTPPayloadContext>> payloadContext;

	protected static Logger logger;

	@Override
	public String getName() {
		return "HttpMatcher";
	}

	@Override
	// TODO Auto-generated method stub
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
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
		// if(true)
		// return Command.STOP;

		OFPacketIn pin = (OFPacketIn) msg;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		if (eth.getEtherType().equals(EthType.IPv4)) {
			IPv4 ip = (IPv4) eth.getPayload();

			if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				logger.warn("Intercepted TCP received outside of GTP. P="
						+ tcp.getDestinationPort() + " A="
						+ ip.getDestinationAddress());
				
				GTPPayloadContext payloadContext = null;
				Map<Integer,GTPPayloadContext> specificIpContextsOnGTPPerPort = null;
				int sourcePort = tcp.getSourcePort().getPort();
				IPv4Address sourceAddress = ip.getSourceAddress();
				int destinationPort = tcp.getDestinationPort().getPort();
				IPv4Address destinationAddress = ip.getDestinationAddress();
				
				
				if(this.payloadContext.containsKey(ip.getSourceAddress())){
					specificIpContextsOnGTPPerPort = this.payloadContext.get(ip.getSourceAddress());
					
					if(specificIpContextsOnGTPPerPort.containsKey(sourcePort)){
						payloadContext = specificIpContextsOnGTPPerPort.get(sourcePort);
					} else {
						payloadContext = new GTPPayloadContext();
					}
				} else {
					specificIpContextsOnGTPPerPort = new HashMap<Integer, GTPPayloadContext>();
					payloadContext = new GTPPayloadContext();
				}
				payloadContext.setTunnelContext(new GTPTunnelContext().updateContext(eth));
				payloadContext.updateContext(ip, pin.getInPort(), sw);
				specificIpContextsOnGTPPerPort.put(sourcePort, payloadContext);
				this.payloadContext.put(ip.getSourceAddress(), specificIpContextsOnGTPPerPort);

				try {
					Enumeration<NetworkInterface> nets = NetworkInterface
							.getNetworkInterfaces();
					for (NetworkInterface netint : Collections.list(nets)) {
						Enumeration<InetAddress> inetAddresses = netint
								.getInetAddresses();

						for (InetAddress inetAddress : Collections
								.list(inetAddresses)) {
							logger.warn("Checking address " + inetAddress);
							if (ip.getDestinationAddress().equals(
									IPv4Address.of(inetAddress))) {
								logger.warn("IP OK, checking port "
										+ tcp.getDestinationPort().getPort());

								if (this.connectedDummyClients.containsKey(tcp
										.getDestinationPort().getPort())) {
									logger.warn("SUCESS! Dummy client found!");
									DummyHTTPClient dummyClient = this.connectedDummyClients
											.get(tcp.getDestinationPort()
													.getPort());

									GTPPayloadContext httpPayloadContext = null;
									int tcpDstPort = dummyClient
											.getDestinationPort();

									if (this.payloadContext
											.containsKey(dummyClient
													.getDestinationAddress())) {
										Map<Integer, GTPPayloadContext> map = this.payloadContext
												.get(dummyClient
														.getDestinationAddress());

										if (map.containsKey(tcpDstPort)) {
											httpPayloadContext = map
													.get(tcpDstPort);
										}
									}

									if (httpPayloadContext == null) {
										throw new RuntimeException(
												"No previous payload for this tunnel, trying to splice a new connection?");
									}

									// ClientTCPSplicingInfo splicingInfo =
									// this.tunnelContexts.get(dummyClient.getSourceAddress()).get(dummyClient.getSourcePort());

									Data data = (Data) tcp.getPayload();
									byte[] bytes = data.getData();

									if (bytes.length > 0) {
										String originalMessage = new String(
												bytes);
										bytes = originalMessage.replace(
												"video", "vedio").getBytes();

										// Ethernet cachedEth =
										// splicingInfo.getContext(bytes);
										// byte[] serializedData =
										// cachedEth.serialize();
										//
										// createAndSendPacketOut(sw,
										// serializedData);
										String s = new String(bytes);
										logger.warn("Size = " + bytes.length
												+ "\n" + s);
										tcp.setPayload(new Data(bytes));
									} else {
										logger.warn("TCP payload "+bytes.length+" control traffic, no data to be sent.");
										return Command.CONTINUE;
									}

									// Ethernet payloadGTPIp =
									// httpPayloadContext.getTunneledPayloadOf(bytes);
									// Ethernet payloadContext =
									// httpPayloadContext.getTunnelContext().getPacketWithPayload(payloadGTPIp);

									// IPv4 ackGTPIp =
									// httpPayloadContext.getTunneledPayloadOf(bytes);
									IPv4 httpGTPed = httpPayloadContext
											.getTunneledPayloadOf(tcp);
//									TCP httpTCPData = httpPayloadContext
//											.getPayloadOf(tcp);

									// Ethernet ack =
									// ackGTPTunnel.getPacketWithPayload(ackGTPIp);
									// Ethernet httpData =
									// httpPayloadContext.getTunnelContext().getPacketWithPayload(ackGTPIp);

									Ethernet httpData = httpPayloadContext
											.getTunnelContext()
											.getPacketWithPayload(httpGTPed);

//									httpData.setPayload(httpTCPData);
//									httpTCPData.setParent(httpData);

									// createAndSendPacketOut(httpPayloadContext.getSw(),
									// httpData.serialize(),
									// httpPayloadContext.getOFPort());

									createAndSendPacketOut(
											httpPayloadContext.getSw(),
											httpData.serialize(), OFPort.FLOOD);

									return Command.CONTINUE;
								}

							}
						}
					}
				} catch (SocketException e) {
					e.printStackTrace();
				}

				
				Data data = (Data) tcp.getPayload();
				byte[] bytes = data.getData();
				logger.warn("Checking TCP payload "+bytes.length);
				
				
				if (bytes.length > 0) {

					String s = new String(bytes);
					String host = "192.168.1.3";
					logger.warn("Testing GET and address "+ip.getDestinationAddress()+" != "+IPv4Address.of(host));
					 
					if (s.contains("GET") && s.contains("HTTP")
							&& s.contains("mp4") && !ip.getDestinationAddress().equals(IPv4Address.of(host))) {
						
						logger.warn("HTTP GET detected, forwarding it to "
								+ host);

						GTPPayloadContext ackPayloadContext = null;

						if (this.payloadContext.containsKey(destinationAddress)) {
							Map<Integer, GTPPayloadContext> map = this.payloadContext
									.get(destinationAddress);

							if (map.containsKey(destinationPort)) {
								ackPayloadContext = map.get(destinationPort);
							}
						}

						if (ackPayloadContext == null) {
							throw new RuntimeException(
									"No previous payload for this tunnel, trying to splice a new connection?");
						}

						GTPPayloadContext getPayloadContext = new GTPPayloadContext();
						getPayloadContext.updateContext(ip, OFPort.FLOOD, sw);
						
						
						IPv4 ackGTPIp = ackPayloadContext.getACK(bytes.length, getPayloadContext.getTsVal(), getPayloadContext.getTsecr());
						// Ethernet ack =
						// ackGTPTunnel.getPacketWithPayload(ackGTPIp);
						Ethernet ack = ackPayloadContext.getTunnelContext()
								.getPacketWithPayload(ackGTPIp);

						// createAndSendPacketOut(
						// ackPayloadContext.getSw(),
						// ack.serialize(),
						// ackPayloadContext.getOFPort());

						createAndSendPacketOut(ackPayloadContext.getSw(),
								ack.serialize(), OFPort.FLOOD);
						
						OFFactory myFactory = sw.getOFFactory();
						
						Match opositMatch = myFactory.buildMatch()
							    .setExact(MatchField.ETH_TYPE, EthType.IPv4)
							    .setMasked(MatchField.IPV4_SRC, IPv4AddressWithMask.of(destinationAddress, IPv4Address.ofCidrMaskLength(32)))
   							    .setMasked(MatchField.IPV4_DST, IPv4AddressWithMask.of(sourceAddress, IPv4Address.ofCidrMaskLength(32)))
							    .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
							    .setExact(MatchField.TCP_SRC, TransportPort.of(destinationPort))
							    .setExact(MatchField.TCP_DST, TransportPort.of(sourcePort))
							    .build();

						List<OFAction> actionList = new ArrayList<OFAction>();

						OFFlowMod flowMod = myFactory.buildFlowAdd().setMatch(opositMatch)
								.setActions(actionList)
								.setHardTimeout(3600)
								.setIdleTimeout(10)
								.setPriority(32768)
								.build();
						sw.write(flowMod);
						
						// ACK -> seq
						// seq -> ACK

						// CHANGE THIS! TODO
						// THIS IS UGLY AS HELL!

						boolean alreadyDownloadingThisData = this
								.checkDummyClients(sourceAddress,
										sourcePort);
						logger.warn("TESTING! Previous client for "
								+ sourceAddress + " " + sourcePort + " r="
								+ alreadyDownloadingThisData);

						if (!alreadyDownloadingThisData) {
							logger.warn("CONFIRMED! No previous client for "
									+ sourceAddress + " " + sourcePort);

							DummyHTTPClient dummyClient = new DummyHTTPClient(
									host, 80, s, this, sourceAddress,
									sourcePort, destinationAddress, destinationPort);
							Thread t = new Thread(dummyClient);
							t.start();
						}

						return Command.STOP;

					}

				}
			}
		}
		
		return Command.CONTINUE;
	}

	private boolean checkDummyClients(IPv4Address iPv4Address, int port) {
		Set<Integer> localPorts = this.connectedDummyClients.keySet();
		for (int localPort : localPorts) {
			DummyHTTPClient client = this.connectedDummyClients.get(localPort);

//			System.out.println("Checking " + client.getSourceAddress() + "=="
//					+ iPv4Address);
//			System.out.println("Checking " + client.getLocalPort() + "=="
//					+ port);

			if (client.getSourceAddress().equals(iPv4Address)
					&& client.getSourcePort() == port) {
				return true;
			}
		}
		return false;
	}

	private void createAndSendPacketOut(IOFSwitch sw, byte[] serializedData,
			OFPort outputPort) {
		OFPacketOut po = sw
				.getOFFactory()
				.buildPacketOut()
				/* mySwitch is some IOFSwitch object */
				.setData(serializedData)
				.setActions(
						Collections.singletonList((OFAction) sw.getOFFactory()
								.actions().output(outputPort, 0xffFFffFF)))
				.setInPort(OFPort.CONTROLLER).build();

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
		this.payloadContext = new HashMap<IPv4Address, Map<Integer, GTPPayloadContext>>();
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);

		logger = LoggerFactory.getLogger(HttpTransparentCache.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {

		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

		// for (Class<? extends IFloodlightService> service : context
		// .getAllServices()) {
		// logger.warn("Name " + service.getSimpleName());
		// }
		//
		// Map<OFType, List<IOFMessageListener>> map = floodlightProvider
		// .getListeners();
		// for (Map.Entry<OFType, List<IOFMessageListener>> entry :
		// map.entrySet()) {
		// logger.warn("Key = " + entry.getKey() + ", Value = "
		// + entry.getValue());
		// }
	}

	public void addConnectedDummyClient(int localPort,
			DummyHTTPClient dummyHTTPClient) {
		logger.warn("WARNING!! Adding a new client"
				+ dummyHTTPClient.toString());

		this.connectedDummyClients.put(localPort, dummyHTTPClient);
	}

	public void delConnectedDummyClient(int localPort) {
		if (this.connectedDummyClients.containsKey(localPort)) {
			// this.connectedDummyClients.remove(localPort);
		}
	}
}
