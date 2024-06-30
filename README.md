# Prototype implementation for the paper Asynchronous Consensus without Trusted Setup or Public-Key Cryptography

## Code structure

This repository is based on https://github.com/sourav1547/htadkg and reuses many implementations (network communication, reliable broadcast protocol, group operation, etc.)

Our new asynchronous consensus is mainly in `adkg/vaba.py`, which includes index cover gather, random rank assignment. A script `scripts/vaba_run.py` is an example for instantiating a node.

The ASKS scheme in the paper is in `adkg/asks.py`. We also provide a benchmark `tests/test_benchmark_asks.py` for it.




## Running on local machine

### Required tools
1. Install `Docker`_. (For Linux, see `Manage Docker as a non-root user`_) to
run ``docker`` without ``sudo``.)

2. Install `docker-compose`

### Building

1. The image will need to be built  (this will likely take a while). Inside the `vaba` folder run
```
$ docker-compose build vaba
```

### Running tests

1. You need to start a shell session in a container. The first run will take longer if the docker image hasn't already been built:
```
$ docker-compose run --rm vaba bash
```

2. Then, to test the `vaba` code locally, i.e., multiple thread in a single docker container, you need to run the following command with parameters:
      - `num`: Number of nodes, 
      - `ths`: fault-tolerance threshold, and

   Note that `n>3*t`
```
pytest tests/test_vaba.py -o log_cli=true --num 4 --ths 1
```
 
## Running locally on multiple processes within a docker image

Note: Required tools and build instructions are same as above

### Running tests
1. Start a docker image by running
```$docker-compose run --rm vaba bash ```

Generate the corresponding configuration files using `gen_config.py`. 

2. Start the VABA instances
```$bash scripts/run_vaba.sh [NUM_NODES]```


## Running in AWS instances
Please refer to `aws/README.md` for detailed information on how to run the protocol using amazon web services

