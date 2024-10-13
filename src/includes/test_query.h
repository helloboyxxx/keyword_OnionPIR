#pragma once

#include "pir.h"
#include "client.h"
#include "server.h"

void run_query_test();

class PirTest {
  public: 

    // only test on the client generate query and server expand query
    void gen_and_expand();

    // An example of "enc then add" trick in generate_query
    void enc_then_add();

    // Testing the noise budget before and after the query expansion
    // void noise_budget_test();
};
