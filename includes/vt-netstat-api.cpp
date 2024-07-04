#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string readApiKey(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open API key file." << std::endl;
        exit(1);
    }
    std::string apiKey;
    std::getline(file, apiKey);
    file.close();
    return apiKey;
}

struct MemoryStruct {
    char* memory;
    size_t size;
};

static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        std::cerr << "Not enough memory (realloc returned NULL)\n";
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string base64_urlencode(const std::string& input) {
    std::string base64_str = base64_encode((const unsigned char*)input.c_str(), input.length());
    std::string result = base64_str;
    size_t padding = base64_str.find('=');
    if (padding != std::string::npos) {
        result = base64_str.substr(0, padding);
    }
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i] == '+') result[i] = '-';
        else if (result[i] == '/') result[i] = '_';
    }
    return result;
}

std::string sha256(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if(context != NULL) {
        if(EVP_DigestInit_ex(context, EVP_sha256(), NULL)) {
            if(EVP_DigestUpdate(context, input.c_str(), input.length())) {
                if(EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
                    EVP_MD_CTX_free(context);

                    std::stringstream ss;
                    for(unsigned int i = 0; i < lengthOfHash; ++i) {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }
                    return ss.str();
                }
            }
        }
        EVP_MD_CTX_free(context);
    }
    return "";
}

std::string getURLReport(const std::string& target_url, const std::string& api_key) {
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = (char*)malloc(1);
    chunk.size = 0;

    std::string url_id = base64_urlencode(target_url);
    std::string url = "https://www.virustotal.com/api/v3/urls/" + url_id;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("x-apikey: " + api_key).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    std::string response(chunk.memory);
    free(chunk.memory);
    curl_global_cleanup();

    return response;
}

void processIPs(const std::string& filename, const std::string& api_key) {
    std::ifstream file(filename);
    std::string ip;
    while (std::getline(file, ip)) {
        std::string response = getURLReport(ip, api_key);
        json decodedResponse = json::parse(response);

        std::string sha_signature = sha256("http://" + ip + "/");
        std::string vt_urlReportLink = "https://www.virustotal.com/gui/url/" + sha_signature;

        std::vector<std::string> keys_to_remove = {
            "last_http_response_content_sha256",
            "last_http_response_code",
            "last_analysis_results",
            "last_final_url",
            "last_http_response_content_length",
            "url",
            "last_analysis_date",
            "tags",
            "last_submission_date",
            "threat_names",
            "last_http_response_headers",
            "categories",
            "last_modification_date",
            "title",
            "outgoing_links",
            "first_submission_date",
            "total_votes",
            "type",
            "id",
            "links",
            "trackers",
            "last_http_response_cookies",
            "html_meta"
        };

        auto& attributes = decodedResponse["data"]["attributes"];
        for (const auto& key : keys_to_remove) {
            if (attributes.contains(key)) {
                attributes.erase(key);
            }
        }

        int community_score = attributes["last_analysis_stats"]["malicious"].is_number() ? attributes["last_analysis_stats"]["malicious"].get<int>() : 0;
        int harmless = attributes["last_analysis_stats"]["harmless"].is_number() ? attributes["last_analysis_stats"]["harmless"].get<int>() : 0;
        int suspicious = attributes["last_analysis_stats"]["suspicious"].is_number() ? attributes["last_analysis_stats"]["suspicious"].get<int>() : 0;
        int undetected = attributes["last_analysis_stats"]["undetected"].is_number() ? attributes["last_analysis_stats"]["undetected"].get<int>() : 0;
        int timeout = attributes["last_analysis_stats"]["timeout"].is_number() ? attributes["last_analysis_stats"]["timeout"].get<int>() : 0;

        int total_vt_reviewers = harmless + community_score + suspicious + undetected + timeout;

        std::string community_score_info = std::to_string(community_score) + "/" + std::to_string(total_vt_reviewers) + "  :  security vendors flagged this as malicious";

        attributes["virustotal report"] = vt_urlReportLink;
        attributes["community score"] = community_score_info;

        // Convert epoch time to human-readable
        time_t epoch_time = attributes["last_analysis_date"].is_number() ? attributes["last_analysis_date"].get<time_t>() : 0;
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%c", localtime(&epoch_time));
        attributes["last_analysis_date"] = time_str;

        std::cout << "\n" << ip << "\n---------------" << std::endl;
        std::cout << "community score: " << community_score_info << std::endl;
        std::cout << "last_analysis_date: " << time_str << std::endl;

        if (attributes.contains("last_analysis_stats")) {
            std::cout << "last_analysis_stats: " << attributes["last_analysis_stats"].dump() << std::endl;
        }

        if (attributes.contains("redirection_chain")) {
            std::cout << "redirection_chain: " << attributes["redirection_chain"].dump() << std::endl;
        }

        if (attributes.contains("reputation")) {
            std::cout << "reputation: " << attributes["reputation"] << std::endl;
        }

        if (attributes.contains("times_submitted")) {
            std::cout << "times_submitted: " << attributes["times_submitted"] << std::endl;
        }

        std::cout << "virustotal report: " << vt_urlReportLink << std::endl;
    }
}

int main() {
    std::string api_key = readApiKey("apikey.txt");
    processIPs("target-ip.txt", api_key);
    return 0;
}

