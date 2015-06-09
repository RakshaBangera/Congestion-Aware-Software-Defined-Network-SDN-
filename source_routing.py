from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

class Controller(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)


    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def switch_in(self, ev):
        dp  = ev.dp
        entered = ev.enter
        if ev.enter:
            self.install_rules(dp)


    def install_rules(self, dp):
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # Make sure the switch's forwarding table is empty
        dp.send_delete_all_flows()
        

        # Creates a rule that sends out packets coming
        # from vlan: vlan to the port: outport
        def from_vlan_to_port(vlan_id, outport):
            match   = ofp_parser.OFPMatch(dl_vlan = vlan_id)
            actions = [ofp_parser.OFPActionOutput(outport)]
            out     = ofp_parser.OFPFlowMod(
                    datapath=dp, cookie=0,
                    command=ofp.OFPFC_ADD,
                    match=match,
                    actions=actions)
            dp.send_msg(out)

        # Rules for different switches
	k = 4
	host_count = (k * k * k)/4
	vlan_count = 1023

	for vlan_id in range (1, vlan_count+1):
	    srcID  = ((vlan_id & 0x0F0)>>4) + 1
	    destID = (vlan_id & 0x00F) + 1 
	    path   = (vlan_id & 0xF00)>>8
	    #print path
            if ( srcID == destID):
	        continue
	    
	    #Directly connected hosts
	    if dp.id in range (1, k*(k/2)+1):
		directly_connected = 0
	        for i in range(1, (k/2)+1):
		    if( destID == (((k/2)*dp.id) - (i-1))):
	                port = (k/2) - (i-1)
			print dp.id, srcID, destID, vlan_id, port
			from_vlan_to_port( vlan_id, port)
			#if( path != 0):
			#    continue
			directly_connected = 1
						
		#Hosts within the same pod
		if directly_connected !=1 :
		    if ((dp.id % (k/2)) !=0):
	                flag = 1
		        for i in range (1, (k/2)+1):
			    pod_addr = ((k/2)*dp.id) - (i-1) + (k/2)
			    if ( destID == pod_addr ):
			        if ( path == 0):
				    print dp.id, srcID, destID,vlan_id, 3
				    from_vlan_to_port(vlan_id, 3)
				elif ( path == 1):
				    print dp.id, srcID, destID, vlan_id, 4
				    from_vlan_to_port(vlan_id, 4)
				#else:
				#    continue
			        flag=0
		        if( flag == 1):
			    if ( (path == 0) or (path == 1)):
				print dp.id, srcID, destID, vlan_id, 3
			    	from_vlan_to_port(vlan_id, 3)
		            elif ((path == 2) or (path == 3)):		
				print dp.id, srcID, destID, vlan_id, 4
				from_vlan_to_port(vlan_id, 4)
	
		    elif ((dp.id % (k/2)) ==0):
			flageven = 1
		        for i in range (1, (k/2)+1):
			    podAddr = (((k/2)*dp.id) - (i-1) - (k/2))
			    if ( destID == podAddr ):
			        if ( path == 0 ):
				    print dp.id, srcID, destID, vlan_id, 4
				    from_vlan_to_port(vlan_id, 4 )
				elif ( path == 1 ):
				    print dp.id, srcID, destID, vlan_id, 3
				    from_vlan_to_port(vlan_id, 3 )
				#else:
				#    continue
				flageven = 0
			if (flageven == 1):
			     if ( (path == 0) or (path == 1)):
				print dp.id, srcID, destID,vlan_id,3
				from_vlan_to_port(vlan_id, 3)
			     elif ( (path == 2) or (path == 3)):
				print dp.id, srcID,destID,vlan_id, 4
				from_vlan_to_port(vlan_id, 4)

	    #Layer 2 Aggregate Switches
	    AggStartIndex = k * (k/2) + 1
	    AggStopIndex  = k * (k/2) * (k/2) +1
	    if dp.id in range( AggStartIndex, AggStopIndex ):
		if ( (dp.id % (k/2)) != 0 ):		
		    lset = 0
		    rset = 0
		    #Hosts within the same pod
		    for i in range(1, (k/2) + 1):
			lswchild = (k/2) * (dp.id - ((k)*(k/2))) -(i-1)
			if ( destID == lswchild ):
			    print dp.id, srcID, destID, vlan_id, 1
			    from_vlan_to_port(vlan_id,1)
			    lset = 1

		    for i in range(1, (k/2) + 1):
			rswchild = (k/2) * (dp.id -((k)*(k/2))) -(i-1) + (k/2)
			if (destID == rswchild ):
			    print dp.id, srcID, destID, vlan_id, 2
			    from_vlan_to_port(vlan_id,2)
			    rset = 1

		    if ((lset != 1) and (rset !=1)):
			if( path == 0):
			    print dp.id, srcID, destID, vlan_id, 3
		            from_vlan_to_port(vlan_id, 3)
			elif( path == 1):
			    print dp.id, srcID, destID, vlan_id, 4
			    from_vlan_to_port(vlan_id, 4)
		   	
		elif ( (dp.id % (k/2)) == 0 ):
		    lcset = 0
		    rcset = 0
		    for i in range(1, (k/2) + 1):
                        leswchild = (k/2) * (dp.id - ((k)*(k/2))) -(i-1) - (k/2)
                        if ( destID == leswchild ):
			    print dp.id, srcID, destID, vlan_id, 1
                            from_vlan_to_port(vlan_id,1)
                            lcset = 1

                    for i in range(1, (k/2) + 1):
                        reswchild = (k/2) * (dp.id -( (k)*(k/2))) -(i-1)
                        if (destID == reswchild ):
			    print dp.id, srcID, destID, vlan_id, 2
                            from_vlan_to_port(vlan_id,2)
                            rcset = 1

                    if ((lcset != 1) and (rcset !=1)):
			if ( path == 2 ):
			    print dp.id, srcID, destID, vlan_id, 3
                            from_vlan_to_port(vlan_id, 3)
			elif ( path == 3 ):
			    print dp.id, srcID, destID, vlan_id, 4
			    from_vlan_to_port(vlan_id, 4)

	    #Core Switches
	    CoreSwIndex = ( k * 2 * (k/2)) + 1
	    CoreSwIndexEnd = CoreSwIndex + k;
	    if dp.id in range( CoreSwIndex, CoreSwIndexEnd):
		hindex = 1
  		for j in range(1, k+1):
	            for i in range (hindex, hindex+k+1):
		    	if destID == i:
			    print dp.id, srcID, destID, vlan_id, j, path
		            from_vlan_to_port(vlan_id,j)  			
		    hindex = hindex + k
