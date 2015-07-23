package br.ufpe.gprt.floodlight.flowMods;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HTTPTrafficFlowModifier implements IOFSwitchListener,
		IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;

	protected static Logger logger;

	@Override
	public void switchAdded(DatapathId switchId) {
		IOFSwitch sw = switchService.getSwitch(switchId);
		OFFactory myFactory = sw.getOFFactory();

		if (myFactory.buildMatch().supports(MatchField.ETH_TYPE)
				&& myFactory.buildMatch().supports(MatchField.IP_PROTO)
				&& myFactory.buildMatch().supports(MatchField.TCP_DST)) {
			logger.warn("Adding flowmod for HTTP redirection to the controller...");

			Match myMatch = myFactory
					.buildMatch()
//					.setExact(MatchField.ETH_TYPE, EthType.IPv4)
					// .set
					// .setMasked(MatchField.IPV4_SRC,
					// IPv4AddressWithMask.of("192.168.0.1/24"))
//					.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
					.setExact(MatchField.TCP_DST, TransportPort.of(80))
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
			sw.write(flowMod);
		}
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		// TODO Auto-generated method stub

	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub

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
		l.add(IOFSwitchService.class);

		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);

		logger = LoggerFactory.getLogger(HTTPTrafficFlowModifier.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		switchService.addOFSwitchListener(this);
	}

}
