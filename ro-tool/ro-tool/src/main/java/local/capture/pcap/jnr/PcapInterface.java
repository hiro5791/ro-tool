package local.capture.pcap.jnr;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

public interface PcapInterface extends Library{
			  
	/**
	 * libpcapエラーを含んだバッファを割り当てる時に使用するサイズ
	 */
	static final int PCAP_ERRBUF_SIZE = 256;
	/**
	 * int pcap_findalldevs	(pcap_if_t** alldevsp, char* errbuf)
	 * @param alldevsp
	 * @param errbuf
	 * @return
	 */
	int pcap_findalldevs(Pointer ppAlldevsp, Pointer pErrbuf);
	
	void pcap_freealldevs(Pointer pAlldevsp);
	
	/**
	 * pcap_t* pcap_open_live(char* device, int snaplen, int promisc, int to_ms, char* ebuf) 
	 * @param device
	 * @param snaplen
	 * @param promisc
	 * @param to_ms
	 * @param pErrbuf
	 * @return
	 */
	Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer pErrbuf);
	
	/**
	 * int pcap_next_ex	(pcap_t * p, struct pcap_pkthdr** pkt_header, u_char** pkt_data)
	 * 戻り値は次のようになります：
	 *  1 パケットが滞りなく読み込まれた時
	 *  0 pcap_open_live()で 設定したタイムアウトが経過した時。この場合はpkt_header と pkt_data は有効なパケットを指しません。
	 *  -1 エラーが発生した時
	 *  -2 オフラインキャプチャからの読み込みがEOFに達した時 
	 * @param p
	 * @param pkt_header
	 * @param pkt_data
	 * @return
	 */
	int pcap_next_ex(Pointer p, Pointer ppPkt_header, Pointer ppPkt_data); 	
	
	 	
	/**
	 * void pcap_close(pcap_t * 	  p) 
	 * @param pPcap_t
	 */
	void pcap_close(Pointer pPcap_t);
	
	/**
	 * char* pcap_geterr(pcap_t* p)
	 * 最後のpcapライブラリエラーに付随するエラーテキストを返します。 
	 * @param pPcap_t
	 * @return
	 */
	Pointer pcap_geterr(Pointer pPcap_t);
}
