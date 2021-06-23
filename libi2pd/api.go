package api

/*
#cgo CXXFLAGS: -I${SRCDIR}/../i18n -I${SRCDIR}/../libi2pd_client -g -Wall -Wextra -Wno-unused-parameter -pedantic -Wno-psabi -fPIC -D__AES__ -maes
#cgo LDFLAGS: -latomic -lcrypto -lssl -lz -lboost_system -lboost_date_time -lboost_filesystem -lboost_program_options -lpthread -lstdc++
*/
import "C"
