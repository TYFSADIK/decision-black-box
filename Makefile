.PHONY: build test demo
build:
	go build -o bin/blackbox ./cmd/blackbox
test:
	go vet ./... && go test -race ./...
demo: build
	rm -f /tmp/bb.jsonl && ./bin/blackbox keygen -key /tmp/bbkeys/bb.key
	./bin/blackbox append -key /tmp/bbkeys/bb.key -log /tmp/bb.jsonl -actor op1 -action track.classify -decision uav -inputs '{"track":7,"confidence":0.86}'
	./bin/blackbox append -key /tmp/bbkeys/bb.key -log /tmp/bb.jsonl -actor op1 -action alert.ack -decision ack -inputs '{"alert":12}'
	./bin/blackbox verify -pub /tmp/bbkeys/bb.pub -log /tmp/bb.jsonl
	./bin/blackbox replay -log /tmp/bb.jsonl
	./bin/blackbox prove -log /tmp/bb.jsonl -seq 1
