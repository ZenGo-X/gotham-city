#!/usr/bin/env bash
docker build -t gotham .
id=$(docker create gotham)
docker cp $id:/gotham-city/gotham-client/jniLibs_debug .
docker cp $id:/gotham-city/gotham-client/jniLibs .
docker rm -v $id
