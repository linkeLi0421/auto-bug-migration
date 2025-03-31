# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/builder
RUN apt-get update && apt-get install -y cmake make
RUN git clone https://github.com/linkeLi0421/Function_instrument.git
WORKDIR Function_instrument
RUN cmake . && make
WORKDIR $SRC/
RUN git clone  https://github.com/Blosc/c-blosc2.git c-blosc2
WORKDIR c-blosc2
COPY build.sh $SRC/