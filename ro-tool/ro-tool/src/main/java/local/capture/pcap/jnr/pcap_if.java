package local.capture.pcap.jnr;

import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class pcap_if extends Structure{
	public static final List<String> FIELDS = createFieldsOrder("next", "name", "description", "addresses", "flags");
	
	/**
	 * pcap_if * 	next
	 * if not NULL, a pointer to the next element in the list; NULL for the last element of the list  
	 */
	public Pointer next;

	/**
	 * char * 	name
	 * a pointer to a string giving a name for the device to pass to pcap_open_live() 
	 */
	public Pointer name;

	/**
	 * char * 	description
	 * if not NULL, a pointer to a string giving a human-readable description of the device
	 */ 
	public Pointer description;
	
	/**
	 * pcap_addr * 	addresses
	 * a pointer to the first element of a list of addresses for the interface
	 */ 
	public Pointer addresses;
	
	/**
	 * u_int 	flags
	 * PCAP_IF_ interface flags. Currently the only possible flag is PCAP_IF_LOOPBACK, that is set if the interface is a loopback interface. 
	 */
	public int flags;

	public pcap_if() {
		super();
	}

	public pcap_if(Pointer p) {
		super(p);
		read();
	}
	
	@Override
    protected List<String> getFieldOrder() {
        return FIELDS;
    }
}
