import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'package:csv/csv.dart';

void main(List<String> args) {
  
  //load file names
  String truthFile = args[0];
  String sguilFile = args[1];
  String argusFile = args[2];

  //empty lists of record objects
  List<Truth> truthRecords = new List();
  List<String> oneRecord = new List();

  // read truth data file into a list of lines
  var lines = new File(truthFile).readAsLinesSync().map((line) => line.trim());
  int lineCount = 0;

  lines.forEach( (line) {
    if(lineCount > 0 && line.startsWith("ID") ) {
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
      String portList = oneRecord.firstWhere((s) => s.startsWith("At_Victim")).split(":")[1].trim();
      if(portList.length > 0) {
          //print("Portlist for parsing: $portList");
          List<String> portSplits = portList.split(", ");
          portSplits.forEach((split) {
              String s = split.substring(0, split.indexOf("{"));
              if(s.contains("/")) {
                  s = s.substring(0, s.indexOf("/"));
              }
    
              if(s != "i"){
                 if(s.contains("-")){
                     int begin = int.parse(s.substring(0, s.indexOf("-")));
                     int end = int.parse(s.substring(s.indexOf("-") + 1));
                     for(int index = begin; index <= end; index++){
                         ports.add(index);
                     }
                 } else {
                     //print("Parsing $s");
                     ports.add(int.parse(s));
                 }
              }
          });
      }

      //new truth record
      var truth = new Truth(id, date, time, duration, 
          attacker, victim, ports);
      //print("Truth record: $truth");
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

  print("Culling truth dates we don't care about");
  truthRecords.removeWhere((truth) => !truth.id.startsWith("43"));
  
  print("Truth count: ${truthRecords.length}");
  print("First ${truthRecords.first}");
  print("Last ${truthRecords.last}");

  //new lists of snort records
  List<Snort> snortRecords = new List();
  oneRecord.clear();

  //read snort export data file into a list of lines
  lines = new File(sguilFile).readAsLinesSync();
  RegExp exp = new RegExp(r"[0-9]+");
  lines.forEach( (line) {
    if(line.startsWith("---------") && oneRecord.length > 0 ) {
      //handle new record
      var line1Splits = oneRecord[0].split(" ");
      var id = line1Splits[1].trim();
      var date = line1Splits[2].trim();
      var time = line1Splits[3].trim();

      var line2Splits = oneRecord[2].split(" -> ");
      var attacker = line2Splits[0].trim();
      var victim = line2Splits[1].trim();

      //print("Line: ${oneRecord[4]}");
      var ints = exp.allMatches(oneRecord[4])
        .map((match) => int.parse(match[0])).toList();
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
  print("First ${snortRecords.first}");
  print("Last ${snortRecords.last}");

  //load argus netflow csv
  List<Netflow> netflowRecords = new List();
  lines = new File(argusFile).readAsLinesSync().skip(1).join("\r\n");
  var rowsAsListOfValues = const CsvToListConverter().convert(lines);
  rowsAsListOfValues.forEach((listOfValues) {
      //print("List length: ${listOfValues.length}");
      assert(listofValues.length == 11);
      //print(listOfValues);
      //ignore mac address records
      if(listOfValues[3].contains(":"))
        return;

      netflowRecords.add(new Netflow(
        listOfValues[0],
        listOfValues[1],
        listOfValues[2],
        listOfValues[3],
        listOfValues[4],
        listOfValues[5],
        listOfValues[6],
        listOfValues[7],
        listOfValues[8],
        listOfValues[9],
        listOfValues[10]));
  });

  print("Netflow count: ${netflowRecords.length}");
  print("First ${netflowRecords.first}");
  print("Last ${netflowRecords.last}");

  int minSeconds = 5 * 60 * 60 - 10;
  int maxSeconds = 5 * 60 * 60 + 10;
  //for each Truth, look for match in snorts
  List<Truth> matches = truthRecords.where((truth) {
      return snortRecords.any((snort) =>
        truth.attacker == snort.attacker &&
        truth.victim == snort.victim &&
        snort.dateTime.difference(truth.dateTime).inSeconds > minSeconds &&
        snort.dateTime.difference(truth.dateTime).inSeconds < maxSeconds &&
        truth.ports.contains(snort.port)
        );
  });

  var matchOutput = matches.join("\n");
  print("Final matches:\n$matchOutput");
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

  Truth(this.id, this.date, this.time, this.duration, 
      this.attacker, this.victim, this.ports){
    var dateSplits = date.split("/");
    var ISO = "${dateSplits[2]}-${dateSplits[0]}-${dateSplits[1]}";
    dateTime = DateTime.parse("$ISO $time");

  }

  String toString() => "ID: $id, Date $date, Time $time, Attacker $attacker, " +
    "Victim $victim Ports: $ports";
}

class Snort {
  String id;
  String date;
  String time;
  String attacker;
  String victim;
  DateTime dateTime;
  int port;

  Snort(this.id, this.date, this.time,
      this.attacker, this.victim, this.port){
    dateTime = DateTime.parse("$date $time");
  }


  String toString() => "ID: $id, Date $date, Time $time, Attacker $attacker, " +
    "Victim $victim, Port $port";

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

  Netflow(String startTime, this.flags, this.proto, this.srcAddress,
      this.srcPort, this.dir, this.destAddress, this.destPort,
      this.packets, this.bytes, this.state){
    this.startTime = DateTime.parse("1999-03-31 $startTime");
  }

  String toString() => "$startTime $srcAddress:$srcPort $destAddress:$destPort $packets";

}

String normalizeIP(String input){
  List<String> splits = input.split(".");
  try{
    List<Int> ints = splits.map((s) => int.parse(s));
    return ints.join(".");
  } catch (_) {
    return input;
  }
}

