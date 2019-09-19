#!/usr/bin/env bash

PRODIR=~/.config/powershell
PROFILE=$PRODIR/Microsoft.PowerShell_profile.ps1
if ! test -d "${PRODIR}"
then
    mkdir -p "${PRODIR}"
fi

if ! test -f "${PROFILE}"
then
    ln -s "$(pwd)/${PROFILE##*/}" "${PROFILE}"
fi
