#!/bin/bash

grep -Po 'password=\K[^&\s]+' logs.txt > passwords.txt
echo "Extracted passwords in passwords.txt"
