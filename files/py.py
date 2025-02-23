import gzip

with gzip.open('graph.svg', 'rb') as f_in:
    with open('graph_unziped.svg', 'wb') as f_out:
        f_out.write(f_in.read())
