# Network Intrusion Detection System Using Random Forests Classifier

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Simulation Scripts](#simulation-scripts)
- [Machine Learning Model Building](#machine-learning-model-building)
- [Demo Script](#demo-script)
- [Important Note](#important-note)

## Overview

This project aims to build a network intrusion detection system using machine learning. The project consists of two parts: simulating network attacks and building a machine learning model. The simulation is done using ns-3, a discrete-event network simulator. The machine learning model is built using Random Forests classifier. The model is trained using the KDD Cup 1999 dataset.

## Prerequisites

Before running the simulations, ensure that ns-3 is installed. Follow the following steps to install ns-3:

1. Clone the ns-3-dev-git repository using `git clone https://github.com/nsnam/ns-3-dev-git`.
2. This should create a new directory called ns-3-dev-git. Move to this directory using `cd ns-3-dev-git`.
3. Run `./ns3 configure --enable-examples --enable-tests` to configure the build.
4. Run `./ns3 build` to build the build.
5. Run `./test.py` to test the build.

The above steps should install ns-3 in the project directory. For more information, refer to the ns-3 documentation.

For building the machine learning model and using the other python scripts, ensure that the following Python libraries are installed:

1. Feature Extraction: pyshark, sys, collections, csv, random
2. Model Build: pandas, numpy, sklearn, pickle
3. Data Exploration: pandas, matplotlib, dash
4. Visualization: dash, numpy, pandas, pickle, plotly

Finally some packages are required for the demo script:

1. TCPdump: `sudo apt-get install tcpdump`
2. Wireshark: `sudo apt-get install wireshark`
3. TShark: `sudo apt-get install tshark`

## Simulation Scripts

The simulation scripts are originally located in the project directory. For executing the simulations, move the DDos.cc and U2R.cc files to the ./ns-3-dev-git/scratch directory using the following commands:

    mv DDos.cc ./ns-3-dev-git/scratch
    mv U2R.cc ./ns-3-dev-git/scratch

The simulation scripts can be executed using the following commands:

    ./ns3 run DDoSim
    ./ns3 run U2R

Each simulation script generates a pcap file in the ./ns-3-dev-git directory. These pcap files can then be used for feature extraction.

## Machine Learning Model Building

Model Building:
Execute Model_Build.ipynb to build a machine learning model.
The model is saved as model.pkl.

Feature Extraction:
Use Feature_Extraction.py to extract features from pcap files.
The output is saved in record.csv.

Data Exploration:
Run DataExplorationKDD.py to observe trends in the input dataset.

## Demo Script

Demo.sh provides a demonstration of simulating attacks using tcpdump and ns-3. Here tcpdump indicates the normal traffic while the pcaps from ns3 simulations indicate the malicious traffic. We have also considered the fact that most of the traffic is usually not an attack by giving lower probabilities for the attack to happen.

Execute this script to observe the simulation process:

    bash Demo.sh

## Important Note

Ensure that the necessary dependencies for the Python scripts are installed. You may need to install additional libraries using a package manager like pip. Also in the case of DDos Simulation, we also generate an xml file for animation. To view the animation, one needs to have the NetAnim software which comes with ns-3-allinone software.

Regarding the Demo, some of the commands may require sudo privileges and the path to the directories and files may need to be changed.

Feel free to explore and modify the scripts based on your requirements. For any issues or questions, refer to the ns-3 documentation or contact the project contributors.
