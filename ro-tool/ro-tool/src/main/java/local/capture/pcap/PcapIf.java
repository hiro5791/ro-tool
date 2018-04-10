package local.capture.pcap;

import java.util.ArrayList;
import java.util.List;

/**
 * Item in a list of interfaces.
 */
public class PcapIf {
	/**
	 *  
	 */
	private String name;

	/**
	 * 
	 */ 
	private String description;

	private List<PcapAddr> addresses = new ArrayList<PcapAddr>(); 
	
	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @param description the description to set
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * @return the addresses
	 */
	public List<PcapAddr> getAddresses() {
		return addresses;
	}
}
