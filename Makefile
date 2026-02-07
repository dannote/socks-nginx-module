NGX_VERSION  := 1.26.3
NGX_SRC      := /root/nginx-$(NGX_VERSION)
MODULE_SRC   := ngx_http_socks_module.c
COMPOSE      := docker compose -f debug/docker-compose.yml
IMAGE        := debug-nginx

# Build the Docker image (cached unless Dockerfile changes)
.PHONY: image
image:
	$(COMPOSE) build nginx

# --- Compilation targets ---

.PHONY: build
build: image
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd $(NGX_SRC) && \
		if [ ! -f /build/Makefile ]; then \
			./configure --with-debug --with-http_ssl_module \
				--builddir=/build --add-dynamic-module=/code; \
		fi && \
		make -f /build/Makefile'

.PHONY: build-clang
build-clang: image
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd $(NGX_SRC) && \
		rm -rf /build-clang && \
		./configure --with-debug --with-http_ssl_module \
			--with-cc=clang \
			--builddir=/build-clang --add-dynamic-module=/code && \
		make -f /build-clang/Makefile'

.PHONY: build-asan
build-asan: image
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd $(NGX_SRC) && \
		if [ ! -f /build-asan/Makefile ]; then \
			./configure --with-debug --with-http_ssl_module \
				--with-cc=clang \
				--with-cc-opt="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
				--with-ld-opt="-fsanitize=address,undefined" \
				--builddir=/build-asan --add-dynamic-module=/code; \
		fi && \
		make -f /build-asan/Makefile'

# --- Testing ---

.PHONY: test
test: build
	bash debug/test.sh

.PHONY: test-asan
test-asan: build-asan
	BUILD_DIR=/build-asan \
	NGINX_ENV="ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:detect_odr_violation=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0" \
	bash debug/test.sh

# --- Static analysis ---

.PHONY: lint
lint: image
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd $(NGX_SRC) && \
		if [ ! -f /build/Makefile ]; then \
			./configure --with-debug --with-http_ssl_module \
				--builddir=/build --add-dynamic-module=/code; \
		fi && \
		clang-tidy /code/$(MODULE_SRC) \
			-checks="-*,bugprone-*,cert-*,clang-analyzer-*,misc-*,performance-*,\
				-bugprone-easily-swappable-parameters,\
				-bugprone-reserved-identifier,\
				-bugprone-multi-level-implicit-pointer-conversion,\
				-bugprone-narrowing-conversions,\
				-cert-dcl37-c,-cert-dcl51-c,\
				-misc-no-recursion,-misc-include-cleaner,-misc-unused-parameters,\
				-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,\
				-bugprone-assignment-in-if-condition,\
				-performance-no-int-to-ptr" \
			-warnings-as-errors="bugprone-*,cert-*" \
			--header-filter="ngx_http_socks_module" \
			-- \
			-I $(NGX_SRC)/src/core \
			-I $(NGX_SRC)/src/event \
			-I $(NGX_SRC)/src/event/modules \
			-I $(NGX_SRC)/src/event/quic \
			-I $(NGX_SRC)/src/os/unix \
			-I /build \
			-I $(NGX_SRC)/src/http \
			-I $(NGX_SRC)/src/http/modules \
			-D NGX_HAVE_EPOLL \
			-include $(NGX_SRC)/src/core/ngx_config.h'

.PHONY: cppcheck
cppcheck: image
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cppcheck /code/$(MODULE_SRC) \
			--enable=warning,performance,portability \
			--error-exitcode=1 \
			--suppress="*:/code/ngx_http_proxy_module.h" \
			--suppress="*:/code/ngx_http_socks_upstream.h" \
			--suppress=toomanyconfigs \
			-I $(NGX_SRC)/src/core \
			-I $(NGX_SRC)/src/event \
			-I $(NGX_SRC)/src/os/unix \
			-I /build \
			-I $(NGX_SRC)/src/http \
			-I $(NGX_SRC)/src/http/modules \
			2>&1'

# --- Formatting ---

.PHONY: format
format:
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd /code && \
		clang-format --dry-run --Werror $(MODULE_SRC)'

.PHONY: format-fix
format-fix:
	$(COMPOSE) run --rm --no-deps nginx bash -c '\
		cd /code && \
		clang-format -i $(MODULE_SRC)'

# --- Aggregate ---

.PHONY: ci
ci: build build-clang format lint cppcheck test
	@echo "All CI checks passed."

.PHONY: clean
clean:
	$(COMPOSE) down -v 2>/dev/null || true
