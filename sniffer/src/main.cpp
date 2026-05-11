#include "db.hpp"
#include "ingest.hpp"

#include <pcap/pcap.h>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int run(const std::string& pcap_path, const std::string& db_path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* p = pcap_open_offline(pcap_path.c_str(), errbuf);
    if (!p) {
        std::fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return 1;
    }
    const int linktype = pcap_datalink(p);

    sniffer::Db db(db_path);
    db.begin();

    struct pcap_pkthdr* hdr = nullptr;
    const std::uint8_t* data = nullptr;
    int rc;
    while ((rc = pcap_next_ex(p, &hdr, &data)) == 1) {
        const std::uint64_t ts_us =
            static_cast<std::uint64_t>(hdr->ts.tv_sec) * 1'000'000ull +
            static_cast<std::uint64_t>(hdr->ts.tv_usec);
        for (const auto& f : sniffer::ingest_packet(linktype, data, hdr->caplen, ts_us)) {
            db.insert_message(f);
        }
    }

    db.commit();
    pcap_close(p);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <pcap> <db>\n", argv[0]);
        return 2;
    }
    return run(argv[1], argv[2]);
}
