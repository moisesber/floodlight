package br.ufpe.gprt.floodlight.transparentCache;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import net.floodlightcontroller.util.FlowModUtils;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
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

public class HttpMatcher implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	private Map<Integer,OFFlowMod> flowModeList;
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
					
					if (!gtp.isControlPacket()) {

						IPv4 gtpIp = (IPv4) gtp.getPayload();
						logger.warn("GTP NOT Control Packet Proto = "+gtpIp.getProtocol());

						if (gtpIp.getProtocol().equals(IpProtocol.TCP)) {

							TCP tcp = (TCP) gtpIp.getPayload();

							if (tcp.getDestinationPort().equals(
									TransportPort.of(80))) {

								Data data = (Data) tcp.getPayload();
								byte[] bytes = data.getData();
								
								if(bytes.length > 0){
									logger.warn("TCP on top of GTP detected!");

									String s = new String(bytes);
									
									if(s.contains("GET") && s.contains("HTTP") && s.contains("mp4")){
										String host = "10.0.0.254";
										logger.warn("HTTP GET detected, forwarding it to "+host);

										DummyHTTPClient dummyClient = new DummyHTTPClient(host, 80, s);
										Thread t = new Thread(dummyClient);
										t.start();
										this.addResponseFlowMod(sw, dummyClient.getLocalPort(), dummyClient.getLocalAddress());
										

									}
								}
							}
						}

						
					}

				}
			} if (ip.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ip.getPayload();
				
				for (int localPort : this.flowModeList.keySet()) {
					if (tcp.getDestinationPort().equals(
							TransportPort.of(localPort))) {

						Data data = (Data) tcp.getPayload();
						byte[] bytes = data.getData();
						
						if(bytes.length > 0){
							logger.warn("Intercepted TCP to localhost received outside of GTP.");

							String s = new String(bytes);
							logger.warn(s);
						}
					}
				}
			}
		}

		return Command.CONTINUE;
	}

	private void addResponseFlowMod(IOFSwitch sw, int localPort, InetAddress inetAddress) {
		OFFactory myFactory = sw.getOFFactory();
		
		Match myMatch = myFactory
				.buildMatch()
//				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				// .set
				// .setMasked(MatchField.IPV4_SRC,
				// IPv4AddressWithMask.of("192.168.0.1/24"))
				.setMasked(MatchField.IPV4_SRC, IPv4AddressWithMask.of(IPv4Address.of((Inet4Address) inetAddress), IPv4Address.ofCidrMaskLength(32)))
				.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
				.setExact(MatchField.TCP_DST, TransportPort.of(localPort))
				.build();

		List<OFAction> actionList = new ArrayList<OFAction>();
		OFActions actions = myFactory.actions();
		OFActionOutput output = actions.buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER).build();
		actionList.add(output);

		OFFlowMod flowMod = myFactory.buildFlowAdd().setMatch(myMatch)
				.setActions(actionList)
				.setHardTimeout(3600)
				.setIdleTimeout(10)
				.setPriority(32768)
				.build();

		this.flowModeList.put(localPort, flowMod);
		sw.write(flowMod);
		sw.flush();
	}
	
	private void delResponseFlowMod(IOFSwitch sw, int localPort) {
		if(this.flowModeList.containsKey(localPort)){
			OFFlowMod flowMod = this.flowModeList.get(localPort);
			OFFlowDelete flowDelete = FlowModUtils.toFlowDelete(flowMod);
			sw.write(flowDelete);
			sw.flush();
		}
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
		this.flowModeList = new HashMap<Integer, OFFlowMod>();
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
}
