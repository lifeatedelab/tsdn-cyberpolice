from fastapi import FastAPI
from nfstream import NFStreamer

my_dataframe = NFStreamer(source="WebattackXSS.pcap").to_pandas()[
    [
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "bidirectional_packets",
        "bidirectional_bytes",
        "application_name",
    ]
]
my_dataframe.head(5)

app = FastAPI()
