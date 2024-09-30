#!/bin/bash

# Set the number of simulations
NUM_SIMULATIONS=10

# Create directory for pcap files if it doesn't exist
mkdir -p pcap_files
rm -rf ./*.pcap pcap_files/*.pcap

# Loop for the specified number of simulations
for ((i=1; i<=$NUM_SIMULATIONS; i++)); do
    # Randomly choose a simulation program
    SIMULATION_PROGRAM=$((1 + RANDOM % 10))

    case $SIMULATION_PROGRAM in
        1)
            # DDoSim.cc
            echo "Running DDoSim simulation..."
            ./ns-3-dev-git/ns3 run DDoSim_pcap

            # Collect pcap files
            echo "Collecting pcap files..."
            mv ./ns-3-dev-git/DDosSim-2-0.pcap "pcap_files/simulation_$i.pcap"
            ;;
        2)
            # U2R.cc
            echo "Running U2R simulation..."
            ./ns-3-dev-git/ns3 run U2R

            # Collect pcap files
            echo "Collecting pcap files..."
            mv ./ns-3-dev-git/U2R-0-1.pcap "pcap_files/simulation_$i.pcap"
            ;;
        *)
            echo "Running non-attack simulation..."
            sudo tcpdump -c 100 -i wlp0s20f3 -w pcap_file2.pcap

            # Collect pcap files
            echo "Collecting pcap files..."
            mv *.pcap "pcap_files/simulation_$i.pcap"
            ;;
    esac

    # Run Python program (replace with the actual name of your Python program)
    echo "Feeding pcap files to Python program..."
    python3 Feature_Extraction.py "pcap_files/simulation_$i.pcap"
    python3 Visualization.py

    # Optionally, clean up simulation artifacts
    rm -rf ./*.pcap pcap_files/*.pcap

    echo "Simulation $i completed."
    echo "----------------------"
done