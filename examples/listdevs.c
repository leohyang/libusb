/*
 * libusb example program to list devices on the bus
 * Copyright © 2007 Daniel Drake <dsd@gentoo.org>
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

#include <stdio.h>
#include <string.h>

#include "libusb.h"

#define  CASTAR_VIB_INTERFACE 

struct libusb_config_descriptor cd;

static void print_devs(libusb_device **devs)
{
	libusb_device *dev;
	libusb_device_handle *dhandle;

	char  istrmanu[32], istrproduct[32], istrsn[32];
	int i = 0, j = 0,k=0,m=0, n=0, alt=0;
	uint8_t path[8]; 

	struct libusb_config_descriptor * cdesc = &cd;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		//r = libusb_get_config_descriptor(dev, k, &cdesc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor\n");
			return;
		}

		libusb_open(dev, &dhandle);
		libusb_get_string_descriptor(dhandle,desc.iManufacturer,0x0409,istrmanu,32);
		libusb_get_string_descriptor(dhandle,desc.iProduct,0x0409,istrproduct,32);
		libusb_get_string_descriptor(dhandle,desc.iSerialNumber,0x0409,istrsn,32);


		printf("\n%04x:%04x (bus %d, device %d) length:%d type:%d version:%04x class:%d SubClass:%d protocol:%d ",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev),
			desc.bLength, desc.bDescriptorType, desc.bcdUSB,
			desc.bDeviceClass, desc.bDeviceSubClass, desc.bDeviceProtocol
			);

		
		printf("\tMaxPktSize0:%d Configurations:%d ",desc.bMaxPacketSize0, desc.bNumConfigurations);
		/*printf("\t\tiManu:%d=%s iProduct:%d=%s iSN:%d=%s\n",desc.iManufacturer, istrmanu,
			desc.iProduct, istrproduct, desc.iSerialNumber,istrsn);*/
			
		r = libusb_get_port_numbers(dev, path, sizeof(path));
			if (r > 0) {
				printf(" path: %d", path[0]);
				for (j = 1; j < r; j++)
					printf(".%d", path[j]);
			}
			printf("\n");



		for ( k = 0; k< desc.bNumConfigurations; k++) {

		   r = libusb_get_config_descriptor(dev, k, &cdesc);

		   if (r < 0) {
			printf("failed to get configuration descriptor\n");
			return;
		   }
		    printf("\tConfiguration bLength:%d bDescType:%d wTotalLeng:%d bNumInterfaces:%d bConfigValue:%d  iConfig:%d bmAttr:0x%x MaxPower:%d mA extra:%d\n",
				 cdesc->bLength, cdesc->bDescriptorType, cdesc->wTotalLength,
				 cdesc->bNumInterfaces, cdesc->bConfigurationValue, cdesc->iConfiguration,
				 cdesc->bmAttributes, cdesc->MaxPower*2, cdesc->extra_length);

			for(m=0; m<cdesc->bNumInterfaces; m++){
				//if (desc.idVendor == 0x03eb) m=1;  segmentation fault, memory is not allocated

				for (alt=0; alt<cdesc->interface[m].num_altsetting; alt++){
					
				printf("\t\tInterface Descriptor bLeng:%d, bDescType:%d bIntNum:%d altSettings:%d bAlterSetting:%d bNumEPs:%d bIntClass:%d bIntSubClass:%d bIntProt:%d iInt:%d, extra:%d\n",
				cdesc->interface[m].altsetting[alt].bLength,
				cdesc->interface[m].altsetting[alt].bDescriptorType,
				cdesc->interface[m].altsetting[alt].bInterfaceNumber,
				cdesc->interface[m].num_altsetting,
				cdesc->interface[m].altsetting[alt].bAlternateSetting,
				cdesc->interface[m].altsetting[alt].bNumEndpoints,
				cdesc->interface[m].altsetting[alt].bInterfaceClass,
				cdesc->interface[m].altsetting[alt].bInterfaceSubClass,
				cdesc->interface[m].altsetting[alt].bInterfaceProtocol,
				cdesc->interface[m].altsetting[alt].iInterface,
				cdesc->interface[m].altsetting[alt].extra_length);

				
				if (cdesc->interface[m].altsetting[alt].bNumEndpoints > 0 ) {
				  for (n=0; n<cdesc->interface[m].altsetting[alt].bNumEndpoints; n++){
					printf("\t\t\tEndpoint Descriptor bLeng:%d bType:%d bAddr:0x%x "
							        "bmAttr:0x%02x wMaxPktSize:%d (%x) bInterval:%d bExtra:%d bytes\n",
						cdesc->interface[m].altsetting[alt].endpoint[n].bLength,
						cdesc->interface[m].altsetting[alt].endpoint[n].bDescriptorType,
						cdesc->interface[m].altsetting[alt].endpoint[n].bEndpointAddress,
						cdesc->interface[m].altsetting[alt].endpoint[n].bmAttributes,
						cdesc->interface[m].altsetting[alt].endpoint[n].wMaxPacketSize,cdesc->interface[m].altsetting[alt].endpoint[n].wMaxPacketSize,
						cdesc->interface[m].altsetting[alt].endpoint[n].bInterval,
						cdesc->interface[m].altsetting[alt].endpoint[n].extra_length);

				  }
				}
			   }						
			}

			//libusb_interface
			//libusb_interface_descriptor
			//libusb_endpoint_descriptor

		}

	    libusb_close(dhandle);


	}
	printf("\n");
}
/////////////////////////////////////////////////////////////////////////////////////////

#ifdef  CASTAR_VIB_INTERFACE

	 int  kVendorID  = 0x20a0;
	 int kProductID = 0x4223;

	  int kMaxISOPackets = 16;
	  int kMaxISOPacketSize = 500;
	  const int kISOBufferSize = 16 * 500;
	
	struct libusb_device_handle *g_vib_hdl = NULL;
	char g_firmware_id[100];
	char g_serial_number[100];
	struct libusb_transfer *g_iso_transfer = NULL;
	char g_iso_buffer[16*500];

    static void check_error(int result ) {
        if (result < 0) {
            printf("\tError=%d %s", result, libusb_error_name(result));
        }
    }
	
	static void open_vib(){
		g_vib_hdl = libusb_open_device_with_vid_pid(NULL, kVendorID, kProductID);
		printf("libusb_open_device_with_vid_pid handle=0x%lx", (long)g_vib_hdl);
	}
	
	static void cleanup() {
		// close the device.
		// shut down libusb.
		// stop the iso transfers
		int result;
		if (g_iso_transfer) {
			printf("cancelling iso transfer...\n");
			libusb_cancel_transfer(g_iso_transfer);
			printf("handle one last event...\n");
			result = libusb_handle_events(NULL);
			check_error(result);
			printf("libusb_free_transfer\n");
			libusb_free_transfer(g_iso_transfer);
			g_iso_transfer = NULL;
		}
		if (g_vib_hdl) {
			printf("releasing interface...\n");
			result = libusb_release_interface(g_vib_hdl, 0);
			printf("libusb_release_interface ret=%d", result);

			printf("libusb_close\n");
			libusb_close(g_vib_hdl);
			g_vib_hdl = NULL;
		}
		printf("libusb_exit\n");
		libusb_exit(NULL);
		printf("cleanup\n");
	}

	static void get_firmware_id() {
		int result;
		printf("getting firmware id...\n");
		memset(g_firmware_id, 0, sizeof(g_firmware_id));
		result = libusb_control_transfer(
			g_vib_hdl,
			/*request_type=*/ 0xC1, // magic number
			/*bRequest=*/ 3,        // magic number
			/*wValue=*/ 0,
			/*wIndex=*/ 0,
			(unsigned char *) g_firmware_id, sizeof(g_firmware_id)-1,
			/*timeout=*/ 0);
		printf("libusb_control_transfer=%d  firmware_id=%s", result, g_firmware_id);
		check_error(result);
	}
	
	// the vib cold starts in BOOT mode.
	// we have to manually switch it to MAIN mode.
	// this is so we can always recover if we accidentally brick MAIN mode.
	static void run_main_from_boot() {
		auto result = libusb_init(NULL);
		printf( "libusb_init=%d", result);
		if (result < 0) {
			check_error(result);
			return;
		}
		
		open_vib();
		if (g_vib_hdl == NULL) {
			return;
		}
		
		// firmware id is BOOTblah or MAINblah.
		get_firmware_id();
		
		// switch to MAIN if currently in BOOT.
		// this will restart the device.
		if (memcmp(g_firmware_id, "BOOT", 4) == 0) {
			printf("In BOOT mode. Switching to MAIN...\n");
			result = libusb_control_transfer(
				g_vib_hdl,
				/*request_type=*/ 0x41, // magic number
				/*bRequest=*/ 2,        // magic number
				/*wValue=*/ 0,
				/*wIndex=*/ 0,
				NULL, 0,
				/*timeout=*/ 0);
			printf ( "libusb_control_transfer(reset)= %d", result);
			check_error(result);
		} else {
			printf("Already in MAIN run mode. No need to reset.\n");
		}
		
		// we might have restarted the device.
		// so shut down everything.
		// and start fresh.
		cleanup();
	}
	
	// we might have to wait for the device to (re)start.
	static void reopen_with_retries() {
		auto result = libusb_init(NULL);
		printf ( "libusb_init=%d", result);
		if (result < 0) {
			check_error(result);
			return;
		}
		
		auto retry = 0;
		for(;;) {
			open_vib();
			if (g_vib_hdl) {
				break;
			}
			
			++retry;
			if (retry >= 5) {
				printf ( "Error: Giving up trying to open vib device.\n");
				return;
			}
			sleep(1); //std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
	
	static void get_serial_number()  {
		int i;
		printf ( "getting serial number...\n");
		unsigned char serialnumber[2*sizeof(g_serial_number)];
		memset(serialnumber, 0, sizeof(serialnumber));
		auto count = libusb_get_string_descriptor(
			g_vib_hdl,
			/*desc_index=*/ 0x03,
			/*langid=*/ 0x0409,  // united states english
			serialnumber, sizeof(serialnumber));
		// convert the serial number from a 2 byte string to a 1 byte string.
		memset(g_serial_number, 0, sizeof(g_serial_number));
		for ( i = 0; i < count; i += 2) {
			g_serial_number[i/2] = serialnumber[i];
		}
		printf ("libusb_get_string_descriptor=%d serialnumber=%s", count, g_serial_number);;
		check_error(count);
	}

	char  ptr[64];

	static void parse_vib_config() {
	
		struct libusb_config_descriptor * cd1;
		char * ptr1, * dir;
		int i, k, in_endpoint;
		struct libusb_interface_descriptor * id;
		struct libusb_endpoint_descriptor * ed;
		uint8_t attrs;
		char * type;

		
		printf ( "getting device descriptor...\n");
		// caution: libusb_device_descriptor is a superset of the 
		// data returned by get descriptor. 
		struct libusb_device_descriptor dd;
		memset(&dd, 0, sizeof(dd));
		auto count = libusb_get_descriptor(
			g_vib_hdl,
			LIBUSB_DT_DEVICE,
			/*desc_index=*/ 0,
			(unsigned char *) &dd, LIBUSB_DT_DEVICE_SIZE);
		printf ( "libusb_get_descriptor device(18)= %d  bNumConfigurations=%d", count, dd.bNumConfigurations) ;
		check_error(count);
	
		printf("getting config descriptor size...\n");
		// caution: libusb_config_descriptor is a superset of the 
		// data returned by get descriptor. 
		struct libusb_config_descriptor cd;
		memset(&cd, 0, sizeof(cd));
		count = libusb_get_descriptor(
			g_vib_hdl,
			LIBUSB_DT_CONFIG,
			/*desc_index=*/ 0,
			// don't use sizeof(dd)
			(unsigned char *) &cd, LIBUSB_DT_CONFIG_SIZE);
		printf("libusb_get_descriptor config=%d size=%d",count, cd.wTotalLength);
		check_error(count);
	
		printf("getting config descriptor...\n");
		 //ptr = new(std::nothrow) unsigned char[cd.wTotalLength];
		if (ptr == NULL) {
			printf("gah! new char[ %d ]=NULL", cd.wTotalLength);
			return;
		}
		memset(ptr, 0, cd.wTotalLength);
		count = libusb_get_descriptor(
			g_vib_hdl,
			LIBUSB_DT_CONFIG,
			/*desc_index=*/ 0,
			(unsigned char *) ptr, cd.wTotalLength);
		cd1 = (struct libusb_config_descriptor *) ptr;
		ptr1 = ptr + LIBUSB_DT_CONFIG_SIZE;
		printf("libusb_get_descriptor config=%d interfaces=%d value=%d", count, cd1->bNumInterfaces, cd1->bConfigurationValue);
		check_error(count);
		// why less than or equal to? no idea.
		for ( i = 0; i <= cd1->bNumInterfaces; ++i) {
			id = (struct libusb_interface_descriptor *) ptr1;
			ptr1 += LIBUSB_DT_INTERFACE_SIZE;
			printf("interface=%d alt=%d endpoints=%d", i,  id->bAlternateSetting, id->bNumEndpoints);
			for ( k = 0; k < id->bNumEndpoints; ++k) {
				ed = (struct libusb_endpoint_descriptor *) ptr1;
				ptr1 += LIBUSB_DT_ENDPOINT_SIZE;
				in_endpoint = ((ed->bEndpointAddress & 0x80) != 0);
				dir = (in_endpoint) ? "IN" : "OUT";
				int addr = ed->bEndpointAddress & 0x0F;

				attrs = ed->bmAttributes & 0x03;
				switch (attrs) {
				case LIBUSB_TRANSFER_TYPE_BULK:
					type = "BULK";
					break;
				case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
					type = "ISO";
					break;
				default:
					type = "OTHERS";
					break; 
				}
				printf("endpoint=%d, dir=%s, addr=0x%x type=%s bmAttributes_03=%d", k, dir, addr, type, attrs); 
			}
		}

		//delete[] ptr;
	}

	static void select_vib_config() {
		printf("setting configuration...\n");
		auto result = libusb_set_configuration(g_vib_hdl, 1);
		printf("libusb_set_configuration result=%d", result);
		check_error(result);
	
		// claim the interface that has iso transfers.
		printf("claiming interface...\n");
		result = libusb_claim_interface(g_vib_hdl, 0);
		printf("libusb_claim_interface result=%d", result);
		check_error(result);

		// switch to the alternate setting that uses iso transfers.
		printf("setting alt interface...\n");
		result = libusb_set_interface_alt_setting(g_vib_hdl, 0, 1);
		printf("libusb_set_interface_alt_setting  result=%d", result);
		check_error(result);
	}

	static void iso_callback(
		struct libusb_transfer *xfr
	)  {
		//printf("iso_callback xfr=" << xfr);
		int i;
		struct libusb_iso_packet_descriptor * pd;
		if (xfr->status == LIBUSB_TRANSFER_CANCELLED) {
			printf("iso_callback cancelled\n");
			return;
		}

		printf("iso_callback packets=%d", xfr->num_iso_packets);
		for (i = 0; i < xfr->num_iso_packets; ++i) {
			pd = &xfr->iso_packet_desc[i];
			printf("iso_callback packet=%d length=%d actual_length=%d", i, pd->length, pd->actual_length);
		}
		
		auto result = libusb_submit_transfer(xfr);
		if (result < 0) {
			printf("libusb_submit_transfer=%d", result);
			check_error(result);
		}
	}

	static void init_iso_transfers() {
		printf("allocating iso transfer...\n");
		g_iso_transfer = libusb_alloc_transfer(16);
		printf("libusb_alloc_transfer returnPtr=%lx for 16 iso packets", (long)g_iso_transfer);

		printf("filling iso transfer...\n");
		libusb_fill_iso_transfer(
			g_iso_transfer,
			g_vib_hdl,
			/*endpoint=*/ 0x83, // iso in
			(unsigned char *) g_iso_buffer, sizeof(g_iso_buffer),
			/*num_iso_packets=*/ kMaxISOPackets,
			iso_callback,
			/*user_data=*/ NULL,
			/*timeout=*/ 20);

		printf("setting iso packet size...\n");
		libusb_set_iso_packet_lengths(g_iso_transfer, kMaxISOPacketSize);

		printf("submitting iso transfer...\n");
		int result = libusb_submit_transfer(g_iso_transfer);
		printf("libusb_submit_transfer result=%d", result);
		check_error(result);
	}


void init_usb() {
	printf("init_usb\n");
	
	// go to main run mode from boot run mode if necessary.
	// tk tsc to do: bail immediately if there is no vib.
	run_main_from_boot();
	
	// reopen the device. retry if necessary.
	// we can ask faster than it can switch to main from boot.
	reopen_with_retries();
	if (g_vib_hdl == NULL) {
		return;
	}
	
	// verify we are in MAIN
	get_firmware_id();
	if (memcmp(g_firmware_id, "MAIN", 4)) {
		printf("Error: Not in MAIN run mode.\n");
		return;
	}
	
	get_serial_number();

	// get and parse the device configuration.
	// we're looking for the bulk in/out and iso endpoints.
	parse_vib_config();
	
	// presumably we've found what we're looking for.
	select_vib_config();

	// initialize iso transfers
	init_iso_transfers();

	printf("bulk transfer request storage.\n");
	unsigned char data4[4];
	data4[0] = 's';
	data4[1] = 0;
	data4[2] = 2;
	data4[3] = 'r';
	int bytes_sent = 0;
	int result = libusb_bulk_transfer(
		g_vib_hdl,
		0x02,
		data4, sizeof(data4),
		&bytes_sent,
		20);
	printf("libusb_bulk_transfer=%d  to_send=%d sent=%d", result, sizeof(data4), bytes_sent);
	check_error(result);
}

void exit_usb(){
	printf("exit_usb\n");
	cleanup();
}

void test_usb(){
	int i, result;
	//printf("handleing 10 usb events...\n");
	for ( i = 0; i < 10; ++i) {
		result = libusb_handle_events(NULL);
		if (result < 0) {
			check_error(result);
			break;
		}
	}
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////


int main(void)
{
	libusb_device **devs;
	int r;
	ssize_t cnt;

	r = libusb_init(NULL);
	if (r < 0)
		return r;

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		return (int) cnt;

	print_devs(devs);
	libusb_free_device_list(devs, 1);

#ifdef CASTAR_VIB_INTERFACE
	init_usb();
	test_usb();
	exit_usb();
#endif

	libusb_exit(NULL);
	return 0;
}
