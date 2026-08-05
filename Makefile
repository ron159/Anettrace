
export VERSION	?= 0.4.0
RELEASE		?= 1
export RELEASE
UPSTREAM_BTF_COMMIT ?= d455f001
BUILD_TYPE	?= tracing
export UPSTREAM_BTF_COMMIT BUILD_TYPE

man-target 	:= script/zh_CN/anettrace.8

ROOT		:= $(abspath .)
export ROOT
PREFIX		?= ./output
PREFIX		:= $(abspath $(PREFIX))
MAN_DIR		:= $(PREFIX)/usr/share/man
BCOMP		:= ${PREFIX}/usr/share/bash-completion/completions/
export PREFIX
SCRIPT		= $(ROOT)/script
export SCRIPT
ARCH		?= $(shell uname -m)
TARGET_PLATFORM ?= linux-$(ARCH)
export TARGET_PLATFORM
SOURCE_DIR	:= ~/rpmbuild/SOURCES/anettrace-${VERSION}
PACK_TARGET 	:= anettrace-$(VERSION)-$(TARGET_PLATFORM)-$(BUILD_TYPE)
PACK_PATH	:= $(abspath $(PREFIX)/$(PACK_TARGET))
PACK_NAME	:= $(PACK_TARGET).tar.bz2

all clean:
	make -C src $@

%.8: %.md
	md2man-roff $< > $@

man: $(man-target)

install:
	@mkdir -p $(PREFIX)
	make -C src install

	@mkdir -p ${MAN_DIR}/zh_CN/man8/ ${MAN_DIR}/man8/
	@gzip -c $(SCRIPT)/zh_CN/anettrace.8 > \
		${MAN_DIR}/zh_CN/man8/anettrace.8.gz
	@gzip -c $(SCRIPT)/dropreason.8 > ${MAN_DIR}/man8/dropreason.8.gz
	@ln -sf ../zh_CN/man8/anettrace.8.gz ${MAN_DIR}/man8/anettrace.8.gz

	@mkdir -p $(BCOMP); cd $(BCOMP); cp $(SCRIPT)/bash-completion.sh \
		./anettrace
	@mkdir -p ${PREFIX}/usr/share/fish/vendor_completions.d/; \
		cp $(SCRIPT)/anettrace.fish \
		${PREFIX}/usr/share/fish/vendor_completions.d/anettrace.fish

pack:
	@make clean
	@rm -rf $(PACK_PATH) && mkdir -p $(PACK_PATH)
	make PREFIX=$(PACK_PATH) -C src pack
	@cd $(PREFIX) && tar -cjf $(PACK_NAME) $(PACK_TARGET) &&	\
		echo "$(PREFIX)/$(PACK_NAME) is generated"

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r docs src script Makefile README.md LICENSE ${SOURCE_DIR}/
	@sed -i 's/%{VERSION}/$(VERSION)/' ${SOURCE_DIR}/script/anettrace.spec
	@cd ~/rpmbuild/SOURCES/ && tar -czf anettrace-${VERSION}.tar.gz	\
		anettrace-${VERSION}
	@rpmbuild -D 'dist $(RELEASE)' --target ${ARCH}			\
		-ba ${SOURCE_DIR}/script/anettrace.spec
