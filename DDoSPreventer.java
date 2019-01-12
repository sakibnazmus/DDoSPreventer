package net.floodlightcontroller.ddospreventer;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.statistics.FlowRuleStats;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import net.floodlightcontroller.core.IFloodlightProviderService;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.topology.ITopologyService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javafx.util.Pair;

public class DDoSPreventer implements IOFMessageListener, IFloodlightModule {
	protected static int MAX_FLOW_ENTRY = 100;
	protected static int MIN_FLOW_ENTRY = 80;
	private static int STATE_2_PRIORITY = 10;
	private static int STATE_2_IDLE_TIMEOUT = 1;
	private static int STATE_2_HARD_TIMEOUT = 120;
	
	public static BigInteger packetIn = BigInteger.ZERO;
	
	protected Map<DatapathId, OFPort> flaggedPort;
	
	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected ITopologyService topologyService;
	private IStatisticsService statService;
	protected IDeviceService deviceManagerService;
	private Map<DatapathId, Integer> states;
	private Map<DatapathId, DatapathId> forwardingSwitch;
	private IOFSwitch flaggedSwitch = null;

	//Here we are getting the most utilized port for flagging it
	
	public OFPort getBusiestPort(IOFSwitch sw) {
		if(!sw.getEnabledPortNumbers().isEmpty()) {
			OFPort port = null;
			U64 max = null;
			for(OFPortDesc p: sw.getEnabledPorts()) {
				SwitchPortBandwidth spb = statService.getBandwidthConsumption(sw.getId(), p.getPortNo());
				if(spb != null) {
					if(port == null || spb.getBitsPerSecondRx().compareTo(max) > 0) {
						port = p.getPortNo();
						max = spb.getBitsPerSecondRx();
					}
				}
			}
			if(max != null) {
				return port;
			}
		}
		return null;
	}
	
	//This method installs a flow rule in the flagged switch's 
	//flagged port to drop all incoming flows
	
	public void doDrop(IOFSwitch sw, OFPort flaggedPort) {
		OFFactory factory = sw.getOFFactory();
		Match match = factory.buildMatch()
				.setExact(MatchField.IN_PORT, flaggedPort)
				.build();
		List<OFAction> actions = new ArrayList<>();
		OFFlowAdd.Builder flowAdd = factory.buildFlowAdd();
		flowAdd.setHardTimeout(STATE_2_HARD_TIMEOUT)
				.setIdleTimeout(STATE_2_IDLE_TIMEOUT)
				.setBufferId(OFBufferId.NO_BUFFER)
				.setMatch(match)
				.setPriority(STATE_2_PRIORITY);
		flowAdd.setActions(actions);
		sw.write(flowAdd.build());
	}
	
	public void doForward(IOFSwitch sw, OFMessage msg,OFPort flaggedPort, OFPort forwardingPort, int op) {
		//op 1 for add
		//op 2 for modify
		//op 3 for delete
		
		OFFactory factory = sw.getOFFactory();
		Match match = factory.buildMatch()
				.setExact(MatchField.IN_PORT, flaggedPort)
				.build();
		List<OFAction> actions = new ArrayList<>();
		actions.add(factory.actions().output(forwardingPort, Integer.MAX_VALUE));
		if(op == 1) {
			OFFlowAdd.Builder flowAdd = factory.buildFlowAdd();
			flowAdd.setHardTimeout(60)
					.setBufferId(OFBufferId.NO_BUFFER)
					.setIdleTimeout(5)
					.setMatch(match)
					.setOutPort(forwardingPort)
					.setPriority(1);
			flowAdd.setActions(actions);
			sw.write(flowAdd.build());
		} else if(op == 2) {
			OFFlowModify.Builder flowMod = factory.buildFlowModify();
			flowMod.setHardTimeout(60)
					.setBufferId(OFBufferId.NO_BUFFER)
					.setIdleTimeout(5)
					.setMatch(match)
					.setOutPort(forwardingPort)
					.setPriority(1);
			flowMod.setActions(actions);
			
			sw.write(flowMod.build());
		} else if(op == 3) {
			OFFlowDelete.Builder flowDel = factory.buildFlowDelete();
			flowDel.setMatch(match)
					.setOutPort(forwardingPort);
			flowDel.setActions(actions);
			
			sw.write(flowDel.build());
		}
	}
	
	public Pair<DatapathId, OFPort> getForwardingPort(DatapathId swId, OFPort flaggedPort) {
		Set<Link> links = topologyService.getAllLinks().get(swId);
		DatapathId forwardingSwitch = null;
		OFPort forwardingPort = null;
		U64 min = null;
		for(Link l: links) {
			if(l.getSrc().equals(swId) && !l.getSrcPort().equals(flaggedPort)) {
				if(states.get(l.getDst()) == 0){
					SwitchPortBandwidth spb = statService.getBandwidthConsumption(swId, l.getSrcPort());
					if(spb == null) continue;
					U64 tx = spb.getBitsPerSecondTx();
					if(min == null || tx.compareTo(min)> 0) {
						forwardingSwitch = l.getSrc();
						forwardingPort = l.getSrcPort();
						min = tx;
					}
				}
			}
		}
		
		return new Pair<DatapathId, OFPort>(forwardingSwitch, forwardingPort);
	}
	
	@Override
	public String getName() {
	    return DDoSPreventer.class.getSimpleName();
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
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}
	
	//Initializing all local variables

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    topologyService = context.getServiceImpl(ITopologyService.class);
	    this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
	    statService = context.getServiceImpl(IStatisticsService.class);
	    statService.collectStatistics(true);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(DDoSPreventer.class);
	    flaggedPort = new ConcurrentHashMap<DatapathId, OFPort>();
	    states = new ConcurrentHashMap<DatapathId, Integer>();
	    forwardingSwitch = new ConcurrentHashMap<DatapathId, DatapathId>();
	    packetIn = BigInteger.ZERO;
	    System.out.println("DDoS defender started");
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	
	//This method is called upon for every packet in requests
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		//packetIn = packetIn.add(BigInteger.ONE);
		DatapathId dpId = sw.getId();
		
		//checking whether if the switch is in states HashMap
		//if not, put state 0 to it
		if(!states.keySet().contains(dpId)) {
			states.put(dpId, 0);
		}
		if(states.get(dpId) == 0) {			//If state is 0, then try
											//get the number of flow rules 
											//installed in the switch.
											//if cannot retrieve it
											//print that it can't
			try {
				Set<FlowRuleStats> flow_stats = statService.getFlowStats(sw.getId());
				
				//if flow table size is greater than MAX_THRESHOLD
				//than find flagged port, forwarding switch and then install 
				//a rule to send all mismatched coming at flagged port 
				//towards the forwarding switch
				if(flow_stats.size() > MAX_FLOW_ENTRY) {
					if(flaggedSwitch == null) {
						flaggedSwitch = sw;
					}
					//System.out.println("Switch: " + dpId.toString() +" GOING TO PHASE 1");
					//OFPort flaggedPort = getPortWithMostFlowRules(flow_stats);
					OFPort flaggedPort = getBusiestPort(sw);
					if(flaggedPort != null) {
						this.flaggedPort.put(sw.getId(), flaggedPort);
						Pair<DatapathId, OFPort> forward = getForwardingPort(sw.getId(), flaggedPort);
						DatapathId forwardingSwitch = forward.getKey();
						OFPort forwardingPort = forward.getValue();
						if(forwardingPort != null) {
							doForward(sw, msg, flaggedPort, forwardingPort, 1);
							this.forwardingSwitch.put(dpId, forwardingSwitch);
							states.put(dpId, 1);
						} else if(forwardingPort == null){
							//if it can not find any switch to forward it means that all connected
							//other switch's are busy. Then drop any flow coming towards the flagged port of
							//the flagged switch
							
							doDrop(flaggedSwitch, this.flaggedPort.get(flaggedSwitch.getId()));
							states.put(flaggedSwitch.getId(), 0);
							flaggedSwitch = null;
							this.flaggedPort.remove(flaggedSwitch.getId());
							this.forwardingSwitch.remove(flaggedSwitch.getId());
						}
						return Command.CONTINUE;
					}
				}
			} catch(Exception e) {
				System.out.println("Could not get flow statistcs of Switch: " + dpId);
			}
		} 			
		
		//If the switch is in state 1, then check if it has caused it's forwarding switch to 
		//go to state 1.If yes, then change the forwarding switch. If not and it's flow table size is
		//lower than MIN_THRESHOLD, then go back to state 1.
		//If it cannot find any forwarding switch, then drop any flow coming
		//towards the flagged port of the flagged switch.
		else if(states.get(dpId) == 1) {
			DatapathId currForSwitch = forwardingSwitch.get(dpId);
			if(states.get(currForSwitch) != 0) {
				Pair<DatapathId, OFPort> forward = getForwardingPort(dpId, flaggedPort.get(dpId));
				if(forward.getValue() != null) {
					doForward(sw, msg, flaggedPort.get(dpId), forward.getValue(), 2);
					this.forwardingSwitch.put(dpId, forward.getKey());
				} else {
					System.out.println("No port left to forward. Shutting down switch: " + flaggedSwitch.getId() + " Port: " + flaggedPort.get(flaggedSwitch.getId()));
					doDrop(flaggedSwitch, flaggedPort.get(flaggedSwitch.getId()));
					flaggedSwitch = null;
					flaggedPort.remove(flaggedSwitch.getId());
					states.put(flaggedSwitch.getId(), 0);
				}
			} else {
				Set<FlowRuleStats> frs = statService.getFlowStats(dpId);
				if(frs.size() < MIN_FLOW_ENTRY) {
					forwardingSwitch.remove(dpId);
					states.put(dpId, 0);
					flaggedPort.remove(dpId);
					flaggedSwitch = null;
					doForward(sw, msg. flaggedPort.get(dpId), forward.getValue(), 3);
				}
			}
		}
		
        return Command.CONTINUE;
    }

}
