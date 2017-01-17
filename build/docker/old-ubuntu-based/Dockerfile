FROM ubuntu

RUN apt-get update && apt-get install -y libboost-dev libboost-filesystem-dev \
       libboost-program-options-dev libboost-date-time-dev \
       libssl-dev git build-essential

RUN git clone https://github.com/PurpleI2P/i2pd.git
WORKDIR /i2pd 
RUN make

CMD ./i2pd
