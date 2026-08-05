
export VERSION	?= 0.4.0
RELEASE		?= 1
UPSTREAM_COMMIT ?= a9f13347
BUILD_TYPE	?= dual
export RELEASE UPSTREAM_COMMIT BUILD_TYPE

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

	@mkdir -p ${MAN_DIR}/zh_CN/man8/; gzip -k $(SCRIPT)/zh_CN/*.8;	\
		mv $(SCRIPT)/zh_CN/*.8.gz ${MAN_DIR}/zh_CN/man8

	@mkdir -p ${MAN_DIR}/man8/; gzip -k $(SCRIPT)/*.8; mv		\
		$(SCRIPT)/*.8.gz ${MAN_DIR}/man8/;			\
		cd ${MAN_DIR}/man8/; for i in `ls ../zh_CN/man8/`;	\
		do							\
			if [ ! -f $$i ];then				\
				ln -s ../zh_CN/man8/$$i ./;		\
			fi;						\
		done

	@mkdir -p $(BCOMP); cd $(BCOMP); cp $(SCRIPT)/bash-completion.sh \
		./anettrace

pack:
	@make clean
	@rm -rf $(PACK_PATH) && mkdir -p $(PACK_PATH)
	make PREFIX=$(PACK_PATH) -C src pack
	@cd $(PREFIX) && tar -cjf $(PACK_NAME) $(PACK_TARGET) &&	\
		echo "$(PREFIX)/$(PACK_NAME) is generated"

rpm:
	@make clean
	@rm -rf ${SOURCE_DIR} && mkdir -p ${SOURCE_DIR}
	@cp -r * ${SOURCE_DIR}/
	@sed -i 's/%{VERSION}/$(VERSION)/' ${SOURCE_DIR}/script/anettrace.spec
	@cd ~/rpmbuild/SOURCES/ && tar -czf anettrace-${VERSION}.tar.gz	\
		anettrace-${VERSION}
	@rpmbuild -D 'dist $(RELEASE)' --target ${ARCH}			\
		-ba ${SOURCE_DIR}/script/anettrace.spec
