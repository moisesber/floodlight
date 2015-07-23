package br.ufpe.gprt.floodlight.transparentCache;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
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

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpMatcher implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
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
							logger.warn("TCP on top of GTP detected!");

							TCP tcp = (TCP) gtpIp.getPayload();

							if (tcp.getDestinationPort().equals(
									TransportPort.of(80))) {
								Data data = (Data) tcp.getPayload();
								byte[] bytes = data.getData();
								
								if(bytes.length > 0){
									String s = new String(bytes);
									
									if(s.contains("GET") && s.contains("HTTP") && s.contains("mp4")){
										String host = "10.0.0.254";
										logger.warn("HTTP GET detected, forwarding it to "+host);

										DummyHTTPClient dummyClient = new DummyHTTPClient();
										try {
											dummyClient.connect(host, 80);
											logger.warn("Local port used is "+dummyClient.getLocalPort());
											
											dummyClient.sendRequest(s);
										} catch (IOException e) {
											// TODO Auto-generated catch block
											e.printStackTrace();
										}
										

									}
								}
							}
						}

						
					}

				}
			}
		}

		return Command.CONTINUE;
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
