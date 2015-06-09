from mininet.topo import Topo
class FatTopo(Topo):
    def __init__(self):
	Topo.__init__(self)
	Hosts = [] 
	k = 4
	host_count = ( k * k * k )/4
	switch_count = ( k * 2 * (k/2)) + (k/2) * (k/2)
	
	for i in range (1, host_count + 1):
	    self.addHost('h'+`i`, ip='10.0.0.'+`i`+'/27')

	for i in range (1,  switch_count + 1):
	    self.addSwitch('s'+`i`)

	hindex  = 1
	s1index = 1
	s2index = k * (k/2)
	
	for pod in range( 1, k + 1):
	    for j in range( 1, k/2 + 1):
		if (( j % (k/2) ) == 0):
		    s1index += 1
	        for l in range( 1, k/2 + 1 ):
		    self.addLink('h'+`hindex`, 's'+`s1index`)
		    hindex += 1

	    s1index = (s1index - (k/2))+1
	    for j in range( 1, k/2 + 1):
		if (( j % (k/2)) == 0):
		    s1index += 1
	        for l in range( 1, k/2 + 1):
		    self.addLink('s'+`s1index`, 's'+`s2index + l`)
	    s1index += 1
	    s2index += k/2
    	s2index = (k * (k/2)) + 1
    	s3index = (2 * k * (k/2)) + 1
    	for i in range (1, (k * (k/2)) + 1):
            if (( i % (k/2) ) == 0):
	    	s3index = s3index + 2
	    else:
	    	s3index = (2 * k * (k/2)) + 1
	    self.addLink('s'+`s2index`, 's'+`s3index`)
	    self.addLink('s'+`s2index`, 's'+`s3index+1`)
	    s2index = s2index + 1

    @classmethod
    def create(cls):
	return cls()
topos = {'fattopo': FatTopo.create}
	
