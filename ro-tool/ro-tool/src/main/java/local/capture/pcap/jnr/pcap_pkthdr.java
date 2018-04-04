package local.capture.pcap.jnr;

import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class pcap_pkthdr extends Structure{
	public static final List<String> FIELDS = createFieldsOrder("ts", "caplen", "len");


	/**
	 * timeval ts   
	 * time stamp 
	 */
	public timeval ts;
	/**
	 * bpf_u_int32 	caplen 
	 * length of portion present 
	 */
	public int caplen;
	/**
	 * bpf_u_int32 	len
	 * length this packet (off wire) 
	 */
	public int len;
	
	public pcap_pkthdr() {
		super();
	}

	public pcap_pkthdr(Pointer p) {
		super(p);
		read();
	}
	
	@Override
    protected List<String> getFieldOrder() {
        return FIELDS;
    }
}
