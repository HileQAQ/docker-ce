module github.com/docker/docker

go 1.15

require (
	cloud.google.com/go v0.81.0
	cloud.google.com/go/logging v1.4.2
	code.cloudfoundry.org/clock v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Graylog2/go-gelf v0.0.0-20191017102106-1550ee647df0
	github.com/Microsoft/go-winio v0.4.19
	github.com/Microsoft/hcsshim v0.8.20
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/armon/go-radix v0.0.0-20180808171621-7fddfc383310
	github.com/aws/aws-sdk-go v1.28.11
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/bsphere/le_go v0.0.0-20170215134836-7a984a84b549
	github.com/cilium/ebpf v0.6.2 // indirect
	github.com/cloudflare/cfssl v0.0.0-20180323000720-5d63dbd981b5
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/console v1.0.2 // indirect
	github.com/containerd/containerd v1.5.4
	github.com/containerd/continuity v0.1.0
	github.com/containerd/fifo v1.0.0
	github.com/containerd/go-runc v1.0.0 // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.2
	github.com/coreos/etcd v3.3.25+incompatible // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e // indirect
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/creack/pty v1.1.11
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/deckarep/golang-set v0.0.0-20141123011944-ef32fa3046d9
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c
	github.com/docker/go-metrics v0.0.1
	github.com/docker/go-units v0.4.0
	github.com/docker/libkv v0.2.2-0.20180912205406-458977154600
	github.com/docker/libtrust v0.0.0-20150526203908-9cbd2a1374f4
	github.com/docker/swarmkit v1.12.1-0.20210611195518-2dcf70aafdc9
	github.com/fernet/fernet-go v0.0.0-20180830025343-9eac43b88a5e // indirect
	github.com/fluent/fluent-logger-golang v1.6.1
	github.com/fsnotify/fsnotify v1.4.9
	github.com/godbus/dbus/v5 v5.0.4
	github.com/gofrs/flock v0.7.3 // indirect
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/gogo/protobuf v1.3.2
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/certificate-transparency-go v1.0.20 // indirect
	github.com/google/go-cmp v0.5.5
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.2.0
	github.com/googleapis/gax-go v1.0.3 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645 // indirect
	github.com/hashicorp/consul v0.5.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.0.0
	github.com/hashicorp/go-memdb v0.0.0-20161216180745-cb9a474f84cc
	github.com/hashicorp/go-msgpack v0.5.3 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hashicorp/memberlist v0.2.4
	github.com/hashicorp/serf v0.8.2
	github.com/imdario/mergo v0.3.11
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/ishidawataru/sctp v0.0.0-20210226210310-f2269e66cdee
	github.com/jmespath/go-jmespath v0.3.0 // indirect
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/klauspost/compress v1.12.3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/miekg/dns v1.1.27
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/moby/buildkit v0.8.2-0.20210615162540-9f254e18360a
	github.com/moby/ipvs v1.0.1
	github.com/moby/locker v1.0.1
	github.com/moby/sys v0.0.0-20210722130427-9b0136d132d8 // indirect
	github.com/moby/sys/mount v0.2.0
	github.com/moby/sys/mountinfo v0.4.1
	github.com/moby/sys/signal v0.5.0
	github.com/moby/sys/symlink v0.1.0
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/morikuni/aec v1.0.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.1
	github.com/opencontainers/runc v1.0.1
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/opencontainers/selinux v1.8.2
	github.com/opentracing-contrib/go-stdlib v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.1
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.10.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/rs/xid v1.2.1
	github.com/samuel/go-zookeeper v0.0.0-20150415181332-d0e0d8e11f31 // indirect
	github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/tchap/go-patricia v2.3.0+incompatible
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/tonistiigi/fsutil v0.0.0-20210609172227-d72af97c0eaf
	github.com/tonistiigi/units v0.0.0-20180711220420-6950e57a87ea // indirect
	github.com/vbatts/tar-split v0.11.1
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	go.etcd.io/bbolt v1.3.5
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/genproto v0.0.0-20210517163617-5e0236093d7a
	google.golang.org/grpc v1.37.1
	gotest.tools/v3 v3.0.3
)
