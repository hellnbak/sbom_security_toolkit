FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/sbom_security_toolkit
WORKDIR $SRC/sbom_security_toolkit

RUN pip3 install --no-cache-dir -r fuzzing/engines/python/requirements.txt

COPY .clusterfuzzlite/build.sh $SRC/build.sh
