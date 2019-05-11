FROM ubuntu

RUN apt-get update && apt-get install -y libboost-dev libboost-filesystem-dev \
       libboost-program-options-dev libboost-date-time-dev \
       libssl-dev git build-essential

RUN git clone https://github.com/PurpleI2P/dotnet.git
WORKDIR /dotnet
RUN make

CMD ./dotnet
