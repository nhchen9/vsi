sudo docker build --target kmstool-instance -t kmstool-instance -f containers/Dockerfile.al2 .
sudo docker build --target kmstool-enclave -t kmstool-enclave -f containers/Dockerfile.al2 .
sudo nitro-cli build-enclave --docker-uri kmstool-enclave --output-file kmstool.eif
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
sudo nitro-cli terminate-enclave --enclave-id $ENCLAVE_ID
sudo nitro-cli run-enclave --eif-path kmstool.eif --memory 512 --cpu-count 2 --debug-mode
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
nitro-cli console --enclave-id $ENCLAVE_ID >> out.txt
