#!/bin/bash
if [ "$(type -t droutine)" = "alias" ]; then
    droutine
else
    dotnet test -c:release
fi

