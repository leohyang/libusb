/*
 * libusb example program to measure Atmel SAM3U isochronous performance
 * Copyright (C) 2012 Harald Welte <laforge@gnumonks.org>
 *
 * Copied with the author's permission under LGPL-2.1 from
 * http://git.gnumonks.org/cgi-bin/gitweb.cgi?p=sam3u-tests.git;a=blob;f=usb-benchmark-project/host/benchmark.c;h=74959f7ee88f1597286cd435f312a8ff52c56b7e
 *
 * An Atmel SAM3U test firmware is also available in the above repository.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <libusb.h>

//#include <Ch9.h>
//#include <usb.h>

//TODO: matching OUT EPx,  IN EPx

#define EP_DATA_IN	0x82	      //original 
#define EP_ISO_IN	0x85          //orginal=0x86,  matching EP5 for ISO in
#define EP_ISO_OUT				0x06


static int do_exit = 0;
static struct libusb_device_handle *devh = NULL;

static unsigned long num_bytes = 0, num_xfer = 0;
static struct timeval tv_start;

#define  NUM_OF_PKTS_PER_SUBMIT   (12)
//#define TEST_USB_DESCRIPTOR   (1)

static uint8_t buf[1024*NUM_OF_PKTS_PER_SUBMIT], buf2[1024*NUM_OF_PKTS_PER_SUBMIT]; //buf[2048];
static struct libusb_transfer *s_xfr;
static struct libusb_transfer *s_xfr2;


static void LIBUSB_CALL cb_xfr(struct libusb_transfer *xfr)
{
	unsigned int i, rc;
	#if 0
	if (xfr == s_xfr2 ) rc = libusb_submit_transfer(s_xfr);
	else rc = libusb_submit_transfer(s_xfr2);

	 //ping-pong is very slow with [1024*3*8]
		
	if (rc < 0) {
		//fprintf(stderr, "error re-submitting URB\n");
		printf("   xxx re-submit URB error, did %d transfer", num_xfer);
		exit(1);
	}
	#endif

	if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
		fprintf(stderr, "transfer status %d\n", xfr->status);
		libusb_free_transfer(xfr);
		exit(3);
	}

	if (xfr->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
		for (i = 0; i < xfr->num_iso_packets; i++) {
			struct libusb_iso_packet_descriptor *pack = &xfr->iso_packet_desc[i];

			if (pack->status != LIBUSB_TRANSFER_COMPLETED) {
				fprintf(stderr, "Error: pack %u status %d\n", i, pack->status);
				exit(5);
			}
			//pack0 length:128, actual_length:1024   x 16 for pack0~pack15
			//impact performance, uncomment
			#if 0
			if (i == 0 || i == (xfr->num_iso_packets-1) )
				printf("pack%u length:%u, actual_length:%u\n", i, pack->length, pack->actual_length);
			#endif
			num_bytes += pack->actual_length;
		}
	}

	/* xfr->actual_length is INVALID for iso transfer
	   xfr->length is buffer length
	   length:2048, actual_length:0
	
	printf("length:%u, actual_length:%u\n", xfr->length, xfr->actual_length); // this is wrong for iso
	*/

	#if 0
	for (i = 0; i < xfr->actual_length; i++) {  //  impossbile to print this many, change WR to file
		printf("%02x", xfr->buffer[i]);
		if (i % 16)	printf("\n");
		else if (i % 8)	printf("  ");
		else	printf(" ");
	}
	#endif
	
	num_xfer++;

	#if 1
	if (libusb_submit_transfer(s_xfr) < 0) {
		//fprintf(stderr, "error re-submitting URB\n");
		printf("   xxx re-submit URB error, did %ld transfer", num_xfer);
		exit(1);
	}
	#endif
}




static int benchmark_in(uint8_t ep)
{
	//static uint8_t buf[1024*3*8]; //buf[2048];
	//static struct libusb_transfer *xfr;
	int num_iso_pack = 0;

	if (ep == EP_ISO_IN)
		num_iso_pack = NUM_OF_PKTS_PER_SUBMIT;    //16;   2048 / 16 = 128   //--------------------shit -------------------------

	s_xfr = libusb_alloc_transfer(num_iso_pack);
	if (!s_xfr)
		return -ENOMEM;

	s_xfr2 = libusb_alloc_transfer(num_iso_pack);
	if (!s_xfr2)
		return -ENOMEM;


	if (ep == EP_ISO_IN) {
		libusb_fill_iso_transfer(s_xfr, devh, ep, buf,
				sizeof(buf), num_iso_pack, cb_xfr, NULL, 0);
		libusb_set_iso_packet_lengths(s_xfr, sizeof(buf)/num_iso_pack);

		libusb_fill_iso_transfer(s_xfr2, devh, ep, buf2,
				sizeof(buf2), num_iso_pack, cb_xfr, NULL, 0);
		
		
		libusb_set_iso_packet_lengths(s_xfr2, sizeof(buf2)/num_iso_pack);

		//hook up a resubmitting callfunc, leoh
		//libusb_fill_iso_transfer(s_xfr, devh, ep, buf, sizeof(buf), num_iso_pack, cb_xfr,NULL, 2000 );
	} else
		/* bulk transfer to receive */
		libusb_fill_bulk_transfer(s_xfr, devh, ep, buf,
				sizeof(buf), cb_xfr, NULL, 0);

	gettimeofday(&tv_start, NULL);

	/* NOTE: To reach maximum possible performance the program must
	 * submit *multiple* transfers here, not just one.
	 *
	 * When only one transfer is submitted there is a gap in the bus
	 * schedule from when the transfer completes until a new transfer
	 * is submitted by the callback. This causes some jitter for
	 * isochronous transfers and loss of throughput for bulk transfers.
	 *
	 * This is avoided by queueing multiple transfers in advance, so
	 * that the host controller is always kept busy, and will schedule
	 * more transfers on the bus while the callback is running for
	 * transfers which have completed on the bus.
	 */

	return libusb_submit_transfer(s_xfr);
}

static void measure(void)
{
	struct timeval tv_stop;
	unsigned int diff_msec;
	unsigned long speed;
	gettimeofday(&tv_stop, NULL);

	diff_msec = (tv_stop.tv_sec - tv_start.tv_sec)*1000;
	diff_msec += (tv_stop.tv_usec - tv_start.tv_usec)/1000;
	speed =num_bytes/diff_msec*1000;

	printf("%lu transfers (total %lu bytes) in %u miliseconds => %lu bytes/sec\n",
		num_xfer, num_bytes, diff_msec, speed);
}

static void sig_hdlr(int signum)  /* invoked 1 time, in main() for SIGINT HANDLER*/
{
	switch (signum) {
	case SIGINT:
		measure();
		do_exit = 1;
		break;
	}
}

#ifdef TEST_USB_DESCRIPTOR
void print_endpoint(struct usb_endpoint_descriptor *endpoint)
{
printf(" bEndpointAddress: %02xh\n", endpoint->bEndpointAddress);
printf(" bmAttributes: %02xh\n", endpoint->bmAttributes);
printf(" wMaxPacketSize: %d\n", endpoint->wMaxPacketSize);
printf(" bInterval: %d\n", endpoint->bInterval);
printf(" bRefresh: %d\n", endpoint->bRefresh);
printf(" bSynchAddress: %d\n", endpoint->bSynchAddress);
}


void print_altsetting(struct usb_interface_descriptor *interface)
{
int i;

printf(" bInterfaceNumber: %d\n", interface->bInterfaceNumber);
printf(" bAlternateSetting: %d\n", interface->bAlternateSetting);
printf(" bNumEndpoints: %d\n", interface->bNumEndpoints);
printf(" bInterfaceClass: %d\n", interface->bInterfaceClass);
printf(" bInterfaceSubClass: %d\n", interface->bInterfaceSubClass);
printf(" bInterfaceProtocol: %d\n", interface->bInterfaceProtocol);
printf(" iInterface: %d\n", interface->iInterface);

for (i = 0; i < interface->bNumEndpoints; i++)
print_endpoint(&interface->endpoint[i]);
}


void print_interface(struct usb_interface *interface)
{
int i;

for (i = 0; i < interface->num_altsetting; i++)
print_altsetting(&interface->altsetting[i]);
}


void print_configuration(struct usb_config_descriptor *config)
{
int i;

printf(" wTotalLength: %d\n", config->wTotalLength);
printf(" bNumInterfaces: %d\n", config->bNumInterfaces);
printf(" bConfigurationValue: %d\n", config->bConfigurationValue);
printf(" iConfiguration: %d\n", config->iConfiguration);
printf(" bmAttributes: %02xh\n", config->bmAttributes);
printf(" MaxPower: %d\n", config->MaxPower);

for (i = 0; i < config->bNumInterfaces; i++)
print_interface(&config->interface[i]);
}

#endif

int main(int argc, char **argv)
{
	int rc;
	struct sigaction sigact;

	sigact.sa_handler = sig_hdlr;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);
	
	#ifdef TEST_USB_DESCRIPTOR
	
	struct usb_bus *bus;
	struct usb_device *dev;
	
	usb_init();
	usb_find_busses();
	usb_find_devices();
	
	printf("bus/device idVendor/idProduct\n");
	
	for (bus = usb_busses; bus; bus = bus->next) {
	for (dev = bus->devices; dev; dev = dev->next) {
	int ret, i;
	char string[256];
	usb_dev_handle *udev;
	
	printf("%s/%s %04X/%04X\n", bus->dirname, dev->filename,
	dev->descriptor.idVendor, dev->descriptor.idProduct);
	
	udev = usb_open(dev);
	if (udev) {
	if (dev->descriptor.iManufacturer) {
	ret = usb_get_string_simple(udev, dev->descriptor.iManufacturer, string, sizeof(string));
	if (ret > 0)
	printf("- Manufacturer : %s\n", string);
	else
	printf("- Unable to fetch manufacturer string\n");
	}
	
	if (dev->descriptor.iProduct) {
	ret = usb_get_string_simple(udev, dev->descriptor.iProduct, string, sizeof(string));
	if (ret > 0)
	printf("- Product : %s\n", string);
	else
	printf("- Unable to fetch product string\n");
	}
	
	if (dev->descriptor.iSerialNumber) {
	ret = usb_get_string_simple(udev, dev->descriptor.iSerialNumber, string, sizeof(string));
	if (ret > 0)
	printf("- Serial Number: %s\n", string);
	else
	printf("- Unable to fetch serial number string\n");
	}
	
	usb_close (udev);
	}
	
	if (!dev->config) {
	printf(" Couldn't retrieve descriptors\n");
	continue;
	}
	
	for (i = 0; i < dev->descriptor.bNumConfigurations; i++)
	print_configuration(&dev->config[i]);
	}
	}
	#endif

	rc = libusb_init(NULL);
	if (rc < 0) {
		fprintf(stderr, "Error initializing libusb: %s\n", libusb_error_name(rc));
		exit(1);
	}

	//devh = libusb_open_device_with_vid_pid(NULL, 0x16c0, 0x0763);
	devh = libusb_open_device_with_vid_pid(NULL, 0x03eb, 0x2423);  // 2015.12.09   SAM3U dev board matching
	if (!devh) {
		fprintf(stderr, "Error finding USB device\n");
		goto out;
	}

	rc = libusb_claim_interface(devh, 0);   // orginal=2, matching SAM3U board =0 alternating
	if (rc < 0) {
		fprintf(stderr, "Error claiming interface: %s\n", libusb_error_name(rc));
		goto out;
	}

	rc = libusb_set_interface_alt_setting(devh, 0, 1);
	if (rc < 0 ){
		printf("---libusb_set_interface_alt_setting() failed --- rc=%d \n", rc);
		goto out;
	}
		

	benchmark_in(EP_ISO_IN);

	while (!do_exit) {
		rc = libusb_handle_events(NULL);
		if (rc != LIBUSB_SUCCESS)
			break;
	}

	/* Measurement has already been done by the signal handler. */

	libusb_release_interface(devh, 0);
out:
	if (devh)
		libusb_close(devh);
	libusb_exit(NULL);
	return rc;
}
