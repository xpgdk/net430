#include "enc28j60.h"

#include <msp430.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "spi.h"
#include "uart.h"
#include "stack.h"
#include "mem.h"

#define TX_START	(0x1FFF - 0x600)
#define RX_END		(TX_START-1)

volatile bool enc_idle;

static uint8_t enc_current_bank;
static uint16_t enc_next_packet;
static uint16_t enc_remaining_packet;

static bool defer = false;
static bool gotDeferred = false;
static uint16_t enc_xmit_size = 0;
static uint16_t deferred_id;
static uint16_t deferred_size;
static uint16_t checksum_location;

static void enc_port_init();
static uint8_t enc_rcr(uint8_t reg);
static void enc_wcr(uint8_t reg, uint8_t val);
static uint8_t enc_rcr_m(uint8_t reg);
static void enc_rbm(uint8_t *buf, uint16_t count);
static void enc_wbm(const uint8_t *buf, uint16_t count);
static void enc_bfs(uint8_t reg, uint8_t mask);
static void enc_bfc(uint8_t reg, uint8_t mask);
static void enc_switch_bank(uint8_t new_bank);
static uint16_t enc_phy_read(uint8_t addr);
static void enc_set_rx_area(uint16_t start, uint16_t end);
static void enc_set_mac_addr(const uint8_t *mac_addr);
static void enc_receive_packet(void);
static void enc_write_packet_data(const uint8_t *buf, uint16_t count);

#define READ_REG(reg) enc_read_reg(reg, reg ## _BANK)
static uint8_t enc_read_reg(uint8_t reg, uint8_t bank);

#define READ_MREG(reg) enc_read_mreg(reg, reg ## _BANK)
static uint8_t enc_read_mreg(uint8_t reg, uint8_t bank);

#define SET_REG_BITS(reg, mask) enc_set_bits(reg, reg ## _BANK, mask)
static void enc_set_bits(uint8_t reg, uint8_t bank, uint8_t mask);

#define CLEAR_REG_BITS(reg, mask) enc_clear_bits(reg, reg ## _BANK, mask)
static void enc_clear_bits(uint8_t reg, uint8_t bank, uint8_t mask);

static void net_send_end_internal(void);

void enc_port_init() {
	P1DIR |= ENC_CS;
	P1OUT |= ENC_CS;

	P1DIR &= ~ENC_INT;

	P1IE |= ENC_INT;
	P1IES |= ENC_INT;

	P1OUT |= ENC_CS;
}

void enc_reset(void) {
	P1OUT &= ~ENC_CS;

	spi_send(0xFF);

	P1OUT |= ENC_CS;
}

uint8_t enc_rcr(uint8_t reg) {
	P1OUT &= ~ENC_CS;
	spi_send(reg);
	uint8_t b = spi_send(0xFF); // Dummy
	P1OUT |= ENC_CS;
	return b;
}

void enc_wcr(uint8_t reg, uint8_t val) {
	P1OUT &= ~ENC_CS;
	spi_send(0x40 | reg);
	spi_send(val);
	P1OUT |= ENC_CS;
}

uint8_t enc_rcr_m(uint8_t reg) {
	P1OUT &= ~ENC_CS;
	spi_send(reg);
	spi_send(0xFF);
	uint8_t b = spi_send(0xFF); // Dummy
	P1OUT |= ENC_CS;
	return b;
}

void enc_rbm(uint8_t *buf, uint16_t count) {
	P1OUT &= ~ENC_CS;
	spi_send(0x20 | 0x1A);
	for (int i = 0; i < count; i++) {
		*buf = spi_send(0xFF);
		buf++;
	}
	P1OUT |= ENC_CS;
}

void enc_wbm(const uint8_t *buf, uint16_t count) {
	P1OUT &= ~ENC_CS;
	spi_send(0x60 | 0x1A);
	for (int i = 0; i < count; i++) {
		spi_send(*buf);
		buf++;
	}
	P1OUT |= ENC_CS;
}

void enc_bfs(uint8_t reg, uint8_t mask) {
	P1OUT &= ~ENC_CS;
	spi_send(0x80 | reg);
	spi_send(mask);
	P1OUT |= ENC_CS;
}

void enc_bfc(uint8_t reg, uint8_t mask) {
	P1OUT &= ~ENC_CS;
	spi_send(0xA0 | reg);
	spi_send(mask);
	P1OUT |= ENC_CS;
}

void enc_switch_bank(uint8_t new_bank) {
	if (new_bank == enc_current_bank || new_bank == ANY_BANK) {
		return;
	}
	uint8_t econ1 = enc_rcr(ENC_ECON1);
	econ1 &= ~ENC_ECON1_BSEL_MASK;
	econ1 |= (new_bank & ENC_ECON1_BSEL_MASK) << ENC_ECON1_BSEL_SHIFT;
	enc_wcr(ENC_ECON1, econ1);
	enc_current_bank = new_bank;
}

uint8_t enc_read_reg(uint8_t reg, uint8_t bank) {
	if (bank != enc_current_bank) {
		enc_switch_bank(bank);
	}

	return enc_rcr(reg);
}

void enc_set_bits(uint8_t reg, uint8_t bank, uint8_t mask) {
	if (bank != enc_current_bank) {
		enc_switch_bank(bank);
	}

	enc_bfs(reg, mask);
}

void enc_clear_bits(uint8_t reg, uint8_t bank, uint8_t mask) {
	if (bank != enc_current_bank) {
		enc_switch_bank(bank);
	}

	enc_bfc(reg, mask);
}

uint8_t enc_read_mreg(uint8_t reg, uint8_t bank) {
	if (bank != enc_current_bank) {
		enc_switch_bank(bank);
	}

	return enc_rcr_m(reg);
}

#define WRITE_REG(reg, value) enc_write_reg(reg, reg ## _BANK, value)
void enc_write_reg(uint8_t reg, uint8_t bank, uint8_t value) {
	if (bank != enc_current_bank) {
		enc_switch_bank(bank);
	}

	enc_wcr(reg, value);
}

uint16_t enc_phy_read(uint8_t addr) {
	/*
	 1. Write the address of the PHY register to read
	 from into the MIREGADR register.*/
	WRITE_REG(ENC_MIREGADR, addr);

	/*2. Set the MICMD.MIIRD bit. The read operation
	 begins and the MISTAT.BUSY bit is set.*/
	WRITE_REG(ENC_MICMD, 0x1);

	/*3. Wait 10.24 μs. Poll the MISTAT.BUSY bit to be
	 certain that the operation is complete. While
	 busy, the host controller should not start any
	 MIISCAN operations or write to the MIWRH
	 register.
	 When the MAC has obtained the register
	 contents, the BUSY bit will clear itself.*/

	/* Assuming that we are running at 1MHz, a single cycle is
	 * 1 us */
	__delay_cycles(10);

	uint8_t stat;
	do {
		stat = READ_MREG(ENC_MISTAT);
	} while (stat & ENC_MISTAT_BUSY);

	/*4. Clear the MICMD.MIIRD bit.*/
	WRITE_REG(ENC_MICMD, 0x00);

	/*5. Read the desired data from the MIRDL and
	 MIRDH registers. The order that these bytes are
	 accessed is unimportant.
	 */
	uint16_t ret;
	ret = READ_MREG(ENC_MIRDL) & 0xFF;
	ret |= READ_MREG(ENC_MIRDH) << 8;

	return ret;
}

void enc_phy_write(uint8_t addr, uint16_t value) {
	WRITE_REG(ENC_MIREGADR, addr);
	WRITE_REG(ENC_MIWRL, value & 0xFF);
	WRITE_REG(ENC_MIWRH, value >> 8);

	__delay_cycles(10);

	uint8_t stat;
	do {
		stat = READ_MREG(ENC_MISTAT);
	} while (stat & ENC_MISTAT_BUSY);
}

void enc_set_rx_area(uint16_t start, uint16_t end) {
	WRITE_REG(ENC_ERXSTL, start & 0xFF);
	WRITE_REG(ENC_ERXSTH, (start >> 8) & 0xFFF);

	WRITE_REG(ENC_ERXNDL, end & 0xFF);
	WRITE_REG(ENC_ERXNDH, (end >> 8) & 0xFFF);

	WRITE_REG(ENC_ERXRDPTL, start & 0xFF);
	WRITE_REG(ENC_ERXRDPTH, (start >> 8) & 0xFFF);
}

void enc_set_mac_addr(const uint8_t *mac_addr) {
	WRITE_REG(ENC_MAADR1, mac_addr[0]);
	WRITE_REG(ENC_MAADR2, mac_addr[1]);
	WRITE_REG(ENC_MAADR3, mac_addr[2]);
	WRITE_REG(ENC_MAADR4, mac_addr[3]);
	WRITE_REG(ENC_MAADR5, mac_addr[4]);
	WRITE_REG(ENC_MAADR6, mac_addr[5]);
}

void print_int(const char *name, uint16_t v) {
	char buf[10];
	itoa(v, buf, 16);
	debug_puts(name);
	debug_puts(": ");
	debug_puts(buf);
	debug_puts("\r\n");
}

void enc_write_packet_data(const uint8_t *buf, uint16_t count) {
	enc_wbm(buf, count);
}

void enc_init(const uint8_t *mac) {
	enc_port_init();

	deferred_id = mem_alloc(1500);

	enc_idle = true;
	enc_next_packet = 0x000;

	//enc_reset();

	enc_switch_bank(0);

	uint8_t reg;
	do {
		reg = READ_REG(ENC_ESTAT);
		debug_puthex(reg);
		debug_nl();
		__delay_cycles(5000);
	} while ((reg & ENC_ESTAT_CLKRDY) == 0);

	__delay_cycles(50000);

	debug_puts("Silicon Revision: ");
	debug_puthex(READ_REG(ENC_EREVID));
	debug_nl();

	//SET_REG_BITS(ENC_ECON1, ENC_ECON1_TXRST | ENC_ECON1_RXRST);
	CLEAR_REG_BITS(ENC_ECON1, ENC_ECON1_RXEN);

	SET_REG_BITS(ENC_ECON2, ENC_ECON2_AUTOINC);

	enc_set_rx_area(0x000, RX_END);

	uint16_t phyreg = enc_phy_read(ENC_PHSTAT2);
	debug_puts("PHSTAT2: ");
	debug_puthex(phyreg);
	debug_puts("\r\n");
	phyreg &= ~ENC_PHSTAT2_DPXSTAT;
	debug_puthex(phyreg);
	debug_puts("\r\n");
	enc_phy_write(ENC_PHSTAT2, phyreg);

	phyreg = enc_phy_read(ENC_PHSTAT2);
	debug_puts("PHSTAT2: ");
	debug_puthex(phyreg);
	debug_puts("\r\n");

	phyreg = enc_phy_read(ENC_PHCON1);
	debug_puts("PHCON1: ");
	debug_puthex(phyreg);
	debug_puts("\r\n");
	phyreg &= ~ENC_PHCON_PDPXMD;
	debug_puts("PHCON1: ");
	debug_puthex(phyreg);
	debug_puts("\r\n");
	enc_phy_write(ENC_PHCON1, phyreg);

#if 0
	print_int("ERXSTL", READ_REG(ENC_ERXSTL));
	print_int("ERXSTH", READ_REG(ENC_ERXSTH));

	print_int("ERXNDL", READ_REG(ENC_ERXNDL));
	print_int("ERXNDH", READ_REG(ENC_ERXNDH));
#endif

	/* Setup receive filter to receive
	 * broadcast, multicast and unicast to the given MAC */
	enc_set_mac_addr(mac);
	WRITE_REG(
			ENC_ERXFCON,
			ENC_ERXFCON_UCEN | ENC_ERXFCON_CRCEN | ENC_ERXFCON_BCEN | ENC_ERXFCON_MCEN);

	/* Initialize MAC */
	WRITE_REG(ENC_MACON1,
			ENC_MACON1_TXPAUS | ENC_MACON1_RXPAUS | ENC_MACON1_MARXEN);

	WRITE_REG(
			ENC_MACON3,
			(0x1 << ENC_MACON3_PADCFG_SHIFT) | ENC_MACON3_TXRCEN | /*ENC_MACON3_FULDPX |*/ENC_MACON3_FRMLNEN);

	WRITE_REG(ENC_MAMXFLL, 1518 & 0xFF);
	WRITE_REG(ENC_MAMXFLH, (1518 >> 8) & 0xFF);

	WRITE_REG(ENC_MABBIPG, 0x12);
	WRITE_REG(ENC_MAIPGL, 0x12);
	WRITE_REG(ENC_MAIPGH, 0x0C);

	SET_REG_BITS(ENC_EIE, ENC_EIE_INTIE | ENC_EIE_PKTIE);

	CLEAR_REG_BITS(ENC_ECON1, ENC_ECON1_TXRST | ENC_ECON1_RXRST);
	SET_REG_BITS(ENC_ECON1, ENC_ECON1_RXEN);
}

void enc_handle_int(void) {
	enc_idle = false;
}

uint16_t enc_read_packet(uint8_t *buf, uint16_t count, void *priv) {
	uint16_t l = count;

	if (l > enc_remaining_packet) {
		l = enc_remaining_packet;
	}

	enc_remaining_packet -= l;

	enc_rbm(buf, l);

	return l;
}

void enc_receive_packet(void) {
	/* Receive a single packet */
	uint8_t header[6];
	uint8_t *status = header + 2;

	WRITE_REG(ENC_ERDPTL, enc_next_packet & 0xFF);
	WRITE_REG(ENC_ERDPTH, (enc_next_packet >> 8) & 0xFF);
	enc_rbm(header, 6);

	/* Update next packet pointer */
	enc_next_packet = header[0] | (header[1] << 8);

	uint16_t data_count = status[0] | (status[1] << 8);

	if (status[2] & (1 << 7)) {
		enc_remaining_packet = data_count - 14;
		struct etherheader etherheader;
		enc_rbm((uint8_t*) (&etherheader), 14);
		handle_ethernet(&etherheader, data_count, enc_read_packet, NULL);
		while(enc_remaining_packet > 0) {
			enc_read_packet(status, 6, NULL);
		}
	}

	/* Mark packet as read */
	WRITE_REG(ENC_ERXRDPTL, enc_next_packet & 0xFF);
	WRITE_REG(ENC_ERXRDPTH, (enc_next_packet >> 8) & 0xFF);
	SET_REG_BITS(ENC_ECON2, ENC_ECON2_PKTDEC);
}

void enc_action(void) {
	enc_idle = false;

	uint8_t reg = READ_REG(ENC_EIR);

	if (reg & ENC_EIR_PKTIF) {
		while (READ_REG(ENC_EPKTCNT) > 0) {
			debug_puts("P");
			enc_receive_packet();
		}
	}

}

int16_t net_send_start(struct etherheader *header) {
	int16_t retval = 0;

	bool doDefer = true;

	for (int i = 0; i < 6; i++) {
		if (header->mac_dest[i] != 0) {
			doDefer = false;
			break;
		}
	}

	enc_xmit_size = 0;
	defer = doDefer;
	if (doDefer) {
		if (gotDeferred) {
			// We can only handle one deferred packet
			return -1;
		}
		debug_puts("Writing packet to secondary storage\r\n");
		retval = deferred_id;
	} else {
		debug_puts("Dest: ");
		print_buf(header->mac_dest, 6);
		debug_puts("\r\n");
		WRITE_REG(ENC_ETXSTL, TX_START & 0xFF);
		WRITE_REG(ENC_ETXSTH, TX_START >> 8);

		WRITE_REG(ENC_EWRPTL, TX_START & 0xFF);
		WRITE_REG(ENC_EWRPTH, TX_START >> 8);
		uint8_t control = 0x00; // USE MACON3 defaults
		net_send_data(&control, 1);
	}

	net_send_data((const uint8_t*) header, sizeof(struct etherheader));

	return retval;
}

void net_send_data(const uint8_t *buf, uint16_t count) {
	if (defer) {
		mem_write(deferred_id, enc_xmit_size, buf, count);
	} else {
		enc_write_packet_data(buf, count);
	}
	enc_xmit_size += count;
}

void net_send_end() {
	if (defer) {
		deferred_size = enc_xmit_size;
		return;
	}
	net_send_end_internal();
}

void net_send_end_internal(void) {
	/* Set TX end */
	uint16_t tx_end = TX_START + enc_xmit_size;
	WRITE_REG(ENC_ETXNDL, tx_end & 0xFF);
	WRITE_REG(ENC_ETXNDH, tx_end >> 8);

	debug_puts("Transmitting ");
	debug_puthex(enc_xmit_size);
	debug_puts(" bytes\r\n");

	/* Eratta 12 */
	SET_REG_BITS(ENC_ECON1, ENC_ECON1_TXRST);
	CLEAR_REG_BITS(ENC_ECON1, ENC_ECON1_TXRST);

	CLEAR_REG_BITS(ENC_EIR, ENC_EIR_TXIF);
	SET_REG_BITS(ENC_ECON1, ENC_ECON1_TXRTS);

	/* Busy wait for the transmission to complete */
	while (true) {
		uint8_t r = READ_REG(ENC_ECON1);
		if ((r & ENC_ECON1_TXRTS) == 0)
			break;
		debug_puts(".");
		__delay_cycles(200);
	}

	/* Read status bits */
	uint8_t status[7];
	tx_end++;
	WRITE_REG(ENC_ERDPTL, tx_end & 0xFF);
	WRITE_REG(ENC_ERDPTH, tx_end >> 8);
	enc_rbm(status, 7);

	debug_puts("Transmit done\r\n");
	uint16_t transmit_count = status[0] | (status[1] << 8);
	debug_puts("Transmit count: ");
	debug_puthex(transmit_count);
	debug_puts("\r\n");
	if (status[2] & 0x80) {
		debug_puts("Transmit OK\r\n");
	}
	debug_puthex(status[2]);
	debug_puts("\r\n");
}

void net_send_deferred(int16_t id, uint8_t const *dstMac) {
	struct etherheader header;

	/* First, get the ether header from secondary storage */
	mem_read(id, 0, &header, sizeof(struct etherheader));

	memcpy(header.mac_dest, dstMac, 6);

	debug_puts("Dest: ");
	print_buf(header.mac_dest, 6);
	debug_puts("\r\n");
	WRITE_REG(ENC_ETXSTL, TX_START & 0xFF);
	WRITE_REG(ENC_ETXSTH, TX_START >> 8);

	WRITE_REG(ENC_EWRPTL, TX_START & 0xFF);
	WRITE_REG(ENC_EWRPTH, TX_START >> 8);
	uint8_t control = 0x00; // USE MACON3 defaults
	net_send_data(&control, 1);

	net_send_data(&header, sizeof(struct etherheader));

	/* Next, read data from secondary storage to ENC26J80 */
	uint8_t buf[50];
	for (uint16_t i = sizeof(struct etherheader); i <= deferred_size; i +=
			sizeof(buf)) {
		uint16_t count = sizeof(buf);
		if (count + i > deferred_size) {
			count = deferred_size - i;
		}
		mem_read(id, i, buf, count);
		net_send_data(buf, count);
	}

	net_send_end_internal();
	gotDeferred = false;
}

void net_drop_deferred(int16_t id) {
	gotDeferred = false;
}

void net_send_dummy_checksum(void) {
	uint8_t buf[] = { 0x00, 0x00 };
	if (defer) {
		checksum_location = enc_xmit_size;
	} else {
		uint8_t high = READ_REG(ENC_EWRPTH);
		checksum_location = READ_REG(ENC_EWRPTL) | (high << 8);
	}
	net_send_data(buf, 2);
}

void net_send_replace_checksum(uint16_t checksum) {
	uint8_t buf[2];
	buf[0] = checksum >> 8;
	buf[1] = checksum & 0xFF;
	if (defer) {
		mem_write(deferred_id, checksum_location, buf, 2);
	} else {
		uint8_t cur[2];
		cur[0] = READ_REG(ENC_EWRPTL);
		cur[1] = READ_REG(ENC_EWRPTH);
		WRITE_REG(ENC_EWRPTL, checksum_location & 0xFF);
		WRITE_REG(ENC_EWRPTH, checksum_location >> 8);
		enc_write_packet_data(buf, 2);
		WRITE_REG(ENC_EWRPTL, cur[0]);
		WRITE_REG(ENC_EWRPTH, cur[1]);
	}
}
