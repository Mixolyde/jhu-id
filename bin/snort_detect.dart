import 'dart:convert';
import 'dart:io';
import 'package:csv/csv.dart';

//adjust for 5 hour difference
// ground starts at 8:00, snort/argus at 13:00
int minSeconds = 5 * 60 * 60 - 600;
int maxSeconds = 5 * 60 * 60 + 600;
List<String> oneRecord = new List<String>();
List<String> lines = new List<String>();
List<Truth> truthRecords = new List<Truth>();
List<Netflow> netflowRecords = new List<Netflow>();
int totalNetflowPackets;
String sguilFile;
String suriFile;

void main(List<String> args) {
  print("minSeconds $minSeconds");
  print("maxSeconds $maxSeconds");
  //load file names
  String truthFile = args[0];
  sguilFile = args[1];
  String argusFile = args[2];
  suriFile = args[3];

  //empty lists of record objects
  oneRecord.clear();

  // read truth data file into a list of lines
  lines = new File(truthFile).readAsLinesSync().map((line) => line.trim());
  int lineCount = 0;

  lines.forEach((line) {
    if (lineCount > 0 && line.startsWith("ID")) {
      //handle new record in previous lines
      var id = oneRecord[0].split(":")[1].trim();
      //print("ID: $id");
      var date = oneRecord[1].split(":")[1].trim();
      var times = oneRecord[4].split(":");
      var time = times[1].trim() + ":" + times[2] + ":" + times[3];
      var durSplits = oneRecord[5].split(":");
      Duration duration = new Duration(
          hours: int.parse(durSplits[1]),
          minutes: int.parse(durSplits[2]),
          seconds: int.parse(durSplits[3]));

      var attacker = normalizeIP(oneRecord[6].split(":")[1].trim());
      var victim = normalizeIP(oneRecord[7].split(":")[1].trim());

      List<int> ports = [];
      //locate at_victim line and scan it and following lines for ports
      int portIndex = 0;
      while (!oneRecord[portIndex].contains("At_Victim")) {
        portIndex++;
      }
      //print("Found At_Victim ports at $portIndex");
      while (oneRecord[portIndex].length != 0) {
        String portList;
        if (oneRecord[portIndex].startsWith("At_Victim")) {
          portList = oneRecord[portIndex].split(":")[1].trim();
        } else {
          portList = oneRecord[portIndex];
        }
        if (portList.length > 0) {
          //print("Portlist for parsing: $portList");
          List<String> portSplits = portList.split(", ");
          portSplits.forEach((split) {
            String s = split.substring(0, split.indexOf("{"));
            if (s.contains("/")) {
              s = s.substring(0, s.indexOf("/"));
            }

            if (s != "i") {
              if (s.contains("-")) {
                int begin = int.parse(s.substring(0, s.indexOf("-")));
                int end = int.parse(s.substring(s.indexOf("-") + 1));
                for (int index = begin; index <= end; index++) {
                  ports.add(index);
                }
              } else {
                //print("Parsing $s");
                ports.add(int.parse(s));
              }
            }
          });
        }

        portIndex++;
      }

      //new truth record
      var truth = new Truth(id, date, time, duration, attacker, victim, ports);
      truthRecords.add(truth);

      //reset record lines
      oneRecord.clear();
      oneRecord.add(line);
    } else {
      //add line to record lines
      oneRecord.add(line);
      lineCount++;
    }
  });

  //print("Culling truth dates we don't care about");
  //truthRecords.removeWhere((truth) => !truth.id.startsWith("43"));

  print("Truth count: ${truthRecords.length}");
  print("First ${truthRecords.first}");
  print("Last  ${truthRecords.last}");

  //load argus netflow csv
  //lines = new File(argusFile).readAsLinesSync().skip(1).join("\r\n");
  lines = new File(argusFile).readAsLinesSync().join("\r\n");
  var rowsAsListOfValues = const CsvToListConverter().convert(lines);
  rowsAsListOfValues.forEach((listOfValues) {
    //ignore mac address records
    //if (listOfValues[3].contains(":")) return;

    int srcPort = listOfValues[4] is int
        ? listOfValues[4]
        : parseNetflowPort(listOfValues[4]);
    int destPort = listOfValues[7] is int
        ? listOfValues[7]
        : parseNetflowPort(listOfValues[7]);

    netflowRecords.add(new Netflow(
        listOfValues[0],
        listOfValues[1],
        listOfValues[2],
        listOfValues[3],
        srcPort,
        listOfValues[5],
        listOfValues[6],
        destPort,
        listOfValues[8],
        listOfValues[9],
        listOfValues[10]));
  });

  totalNetflowPackets = netflowRecords.fold(0, (sum, n) => sum + n.packets);

  print(
      "Netflow count: ${netflowRecords.length} packets: $totalNetflowPackets");
  print("First ${netflowRecords.first}");
  print("Last ${netflowRecords.last}");

  snortMatrix();
  suricataMatrix();

}

snortMatrix(){
  //new lists of snort records
  List<Snort> snortRecords = new List();
  oneRecord.clear();

  //read snort export data file into a list of lines
  lines = new File(sguilFile).readAsLinesSync();
  RegExp exp = new RegExp(r"[0-9]+");
  lines.forEach((line) {
    if (line.startsWith("---------") && oneRecord.length > 0) {
      //handle new record
      var line1Splits = oneRecord[0].split(" ");
      var id = line1Splits[1].trim();
      var date = line1Splits[2].trim();
      var time = line1Splits[3].trim();

      var line2Splits = oneRecord[2].split(" -> ");
      var attacker = line2Splits[0].trim();
      var victim = line2Splits[1].trim();

      //print("Line: ${oneRecord[4]}");
      var ints = exp
          .allMatches(oneRecord[4])
          .map((match) => int.parse(match[0]))
          .toList();
      var port = ints[2];

      var snort = new Snort(id, date, time, attacker, victim, port);
      //print("Snort record: $snort");
      snortRecords.add(snort);

      //reset record lines
      oneRecord.clear();
    } else if (!line.startsWith("-------")) {
      //add line to record lines
      oneRecord.add(line);
    }
  });

  print("Snort count: ${snortRecords.length}");
  //print("First ${snortRecords.first}");
  //print("Last  ${snortRecords.last}");

  //for each Truth, look for match in snorts
  List<Truth> matches = truthRecords.where((truth) {
    //print("Match Truth: ${truth.id} ${truth.dateTime}");
    var snortMatches = snortRecords.where((snort) {
      return truth.attacker == snort.attacker &&
          truth.victim == snort.victim &&
          snort.dateTime.difference(truth.dateTime).inSeconds > minSeconds &&
          snort.dateTime.difference(truth.dateTime).inSeconds <
              maxSeconds + truth.duration.inSeconds &&
          truth.ports.contains(snort.port);
    }).toList();
    truth.matches = snortMatches;

    return snortMatches.length > 0;
  }).toList();

  var matchOutput = matches.join("\n");
  print("True Positives matched: ${matches.length}");
  print("False Positives: ${snortRecords.length - matches.length}");
  //print("Final matches:\n$matchOutput");

  int totalMatchingPackets = 0;

  matches.forEach((match) {
    //find packet count
    var netflows =
        netflowRecords.where((netflow) => netflow.matchesTruth(match)).toList();
    int packets = netflows.fold(0, (a, b) => a + b.packets);
    //print("Netflows Count: (${netflows.length}) Packets: $packets");
    totalMatchingPackets += packets;
  });

  //print("Final matching packets: $totalMatchingPackets");
  //print("Count packets into TP, FP, TN, FN");
  int tn = 0;
  int fn = 0;
  int tp = 0;
  int fp = 0;

  netflowRecords
      //.take(1000) // testing sample
      .forEach((n) {
    bool matchesTruth = truthRecords.any((t) => n.matchesTruth(t));
    bool matchesSnort = snortRecords.any((s) => n.matchesSnort(s));
    bool matchesBoth =
        truthRecords.any((t) => n.matchesTruth(t) && t.matches.length > 0);
    //print("$n Matches T/S/B: $matchesTruth $matchesSnort $matchesBoth");
    if (matchesBoth) {
      tp += n.packets;
    } else if (matchesTruth) {
      //matched truth record, but not snort alert, so false negative
      fn += n.packets;
    } else if (matchesSnort) {
      //matched a snort record, but not a truth, so false positive
      fp += n.packets;
    } else {
      //no match is normal traffic
      tn += n.packets;
    }
  });
  
  printMatrix(tp, fp, fn, tn, totalMatchingPackets);

}

suricataMatrix(){
  //new list of suricata records
  List<Suricata> suriRecords = new List();

  //read suricata export data file into a list of lines
  lines = new File(suriFile).readAsLinesSync();
  //print("First Suri Line: ${lines.first.toString()}");

  List<List> parsedList = lines.map((l) => JSON.decode(l)).toList();
  //print("First parsed Suri Line: ${parsedList[0]["src_ip"].toString()}");
  parsedList.forEach((parsedMap) {
    String id = parsedMap["pcap_cnt"];
    DateTime dateTime = DateTime.parse(parsedMap["timestamp"]);
    String attacker = parsedMap["src_ip"];
    String victim = parsedMap["dest_ip"];
    String port = parsedMap["dest_port"];
    
    var suri = new Suricata(id, dateTime, attacker, victim, port);
    suriRecords.add(suri);

  });

  print("Suri count: ${suriRecords.length}");
  //print("First ${suriRecords.first}");
  //print("Last  ${suriRecords.last}");

  //for each Truth, look for match in snorts
  List<Truth> matches = truthRecords.where((truth) {
    //print("Match Truth: ${truth.id} ${truth.dateTime}");
    var suriMatches = suriRecords.where((suri) {
      return truth.attacker == suri.attacker &&
          truth.victim == suri.victim &&
          suri.dateTime.difference(truth.dateTime).inSeconds > minSeconds &&
          suri.dateTime.difference(truth.dateTime).inSeconds <
              maxSeconds + truth.duration.inSeconds &&
          truth.ports.contains(suri.port);
    }).toList();
    truth.matches = suriMatches;

    return suriMatches.length > 0;
  }).toList();

  var matchOutput = matches.join("\n");
  print("True Positives matched: ${matches.length}");
  print("False Positives: ${suriRecords.length - matches.length}");
  //print("Final matches:\n$matchOutput");

  int totalMatchingPackets = 0;

  matches.forEach((match) {
    //find packet count
    var netflows =
        netflowRecords.where((netflow) => netflow.matchesTruth(match)).toList();
    int packets = netflows.fold(0, (a, b) => a + b.packets);
    //print("Netflows Count: (${netflows.length}) Packets: $packets");
    totalMatchingPackets += packets;
  });

  //print("Final matching packets: $totalMatchingPackets");
  //print("Count packets into TP, FP, TN, FN");
  int tn = 0;
  int fn = 0;
  int tp = 0;
  int fp = 0;

  netflowRecords
      //.take(1000) // testing sample
      .forEach((n) {
    bool matchesTruth = truthRecords.any((t) => n.matchesTruth(t));
    bool matchesSuri = suriRecords.any((s) => n.matchesSuri(s));
    bool matchesBoth =
        truthRecords.any((t) => n.matchesTruth(t) && t.matches.length > 0);
    //print("$n Matches T/S/B: $matchesTruth $matchesSuri $matchesBoth");
    if (matchesBoth) {
      tp += n.packets;
    } else if (matchesTruth) {
      //matched truth record, but not snort alert, so false negative
      fn += n.packets;
    } else if (matchesSuri) {
      //matched a suri record, but not a truth, so false positive
      fp += n.packets;
    } else {
      //no match is normal traffic
      tn += n.packets;
    }
  });
  
  printMatrix(tp, fp, fn, tn, totalMatchingPackets);

}

printMatrix(int tp, int fp, int fn, int tn, int totalMatchingPackets){
  //verify
  //print("${tp + fp + fn + tn} == $totalNetflowPackets");
  //print("$tp == $totalMatchingPackets");
  print("Confusion Matrix Packet Counts:");
  print("True Positives|False Positives");
  print("False Negatives|True Negatives");
  print("$tp|$fp");
  print("$fn|$tn");

}

class Truth {
  String id;
  String date;
  String time;
  Duration duration;
  String attacker;
  String victim;
  DateTime dateTime;
  List<int> ports;

  List<Snort> matches = [];

  Truth(this.id, this.date, this.time, this.duration, this.attacker,
      this.victim, this.ports) {
    var dateSplits = date.split("/");
    var ISO = "${dateSplits[2]}-${dateSplits[0]}-${dateSplits[1]}";
    dateTime = DateTime.parse("$ISO $time");
  }

  String toString() =>
      "ID:$id DateTime:$dateTime Att:$attacker " +
      "Vic:$victim Dur:$duration Ports:$ports";
}

class Suricata {
  String id;
  String attacker;
  String victim;
  DateTime dateTime;
  int port;

  Suricata(this.id, this.dateTime, this.attacker, this.victim, this.port) {
  }

  String toString() =>
      "ID:$id DateTime:$dateTime Att:$attacker Vic:$victim Port:$port";
}

class Snort {
  String id;
  String date;
  String time;
  String attacker;
  String victim;
  DateTime dateTime;
  int port;

  Snort(this.id, this.date, this.time, this.attacker, this.victim, this.port) {
    dateTime = DateTime.parse("$date $time");
  }

  String toString() =>
      "ID:$id DateTime:$dateTime Att:$attacker Vic:$victim Port:$port";
}

class Netflow {
  DateTime startTime;
  String flags;
  String proto;
  String srcAddress;
  int srcPort;
  String dir;
  String destAddress;
  int destPort;
  int packets;
  int bytes;
  String state;

  Netflow(
      String startTime,
      this.flags,
      this.proto,
      this.srcAddress,
      this.srcPort,
      this.dir,
      this.destAddress,
      this.destPort,
      this.packets,
      this.bytes,
      this.state) {
    this.startTime = DateTime.parse("$startTime");
  }

  String toString() =>
      "${startTime.toString().substring(11)} $srcAddress:$srcPort $destAddress:$destPort $packets";

  bool matchesTruth(Truth truth) {
    return truth.attacker == srcAddress &&
        truth.victim == destAddress &&
        truth.ports.contains(destPort) &&
        startTime.difference(truth.dateTime).inSeconds >
            minSeconds - truth.duration.inSeconds &&
        startTime.difference(truth.dateTime).inSeconds <
            maxSeconds + truth.duration.inSeconds;
  }

  bool matchesSnort(Snort snort) {
    return snort.attacker == srcAddress &&
        snort.victim == destAddress &&
        snort.port == destPort &&
        startTime.difference(snort.dateTime).inSeconds > -60 &&
        startTime.difference(snort.dateTime).inSeconds < 60;
  }

  bool matchesSuri(Suricata suri) {
    return suri.attacker == srcAddress &&
        suri.victim == destAddress &&
        suri.port == destPort &&
        startTime.difference(suri.dateTime).inSeconds > -60 &&
        startTime.difference(suri.dateTime).inSeconds < 60;
  }
}

String normalizeIP(String input) {
  List<String> splits = input.split(".");
  try {
    List<int> ints = splits.map((s) => int.parse(s));
    return ints.join(".");
  } catch (_) {
    return input;
  }
}

int parseNetflowPort(String netPort) {
  if (netPort.length == 0) {
    return null;
  } else {
    return int.parse(netPort);
  }
}
