CC := clang
CFLAGS := -Wall -Wextra -O2 -std=c11 -Iinclude -I. $(shell pkg-config --cflags libimobiledevice-1.0 libirecovery-1.0 libusb-1.0 libplist-2.0 openssl libcurl)
LDFLAGS := $(shell pkg-config --libs libimobiledevice-1.0 libirecovery-1.0 libusb-1.0 libplist-2.0 openssl libcurl) -lpthread

SRCS = src/main.c \
       src/core/target.c \
       src/core/log.c \
       src/core/util.c \
       src/usb/port_dfu.c \
       src/usb/usb_ctrl.c \
       src/lockdown/lockdown_unauth.c \
       src/lockdown/session_manager.c \
       src/lockdown/services.c \
       src/lockdown/afc_manager.c \
       src/lockdown/flag_injector.c \
       src/lockdown/crash_reporter.c \
       src/lockdown/lockdown_ssl_bypass.c \
       src/activation/mobileactivation.c \
       src/activation/albert_client.c \
       src/activation/record_a18.c \
       src/activation/ingest_parser.c \
       src/exploits/preboard_poc.c \
       src/exploits/preboard_triage.c \
       src/exploits/preboard_exploit.c \
       src/exploits/springboard_injector.c \
       src/exploits/bypass_chain.c \
       src/exploits/kernel_exploit.c \
       src/exploits/applejpegdriver_exploit.c \
       src/exploits/device_payload.c \
       src/exploits/pmap_exploit.c \
       src/exploits/pmap_device_payload.c \
       src/exploits/applemcc_exploit.c \
       src/exploits/amfi_bypass.c \
       src/exploits/coretrust_bypass.c \
       src/exploits/cvmserver_exploit.c \
       src/exploits/sep_bypass.c \
       src/exploits/sandbox_escape.c \
       src/exploits/tls_bypass.c \
       src/exploits/captive_server.c \
       src/exploits/captive_dns.c \
       src/exploits/captive_http.c \
       src/exploits/captive_payloads.c \
       src/exploits/captive_tls.c \
       src/exploits/appleave2_exploit.c \
       src/exploits/appleave2_device_payload.c

OBJS = $(SRCS:.c=.o)
TARGET = l0fck

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean payload-v047 payload-pmap payload-appleave2

payload-v047:
	$(MAKE) -C payloads/v047 SDK=iphoneos

payload-pmap:
	$(MAKE) -C payloads/pmap SDK=iphoneos

payload-appleave2:
	$(MAKE) -C payloads/appleave2 SDK=iphoneos
