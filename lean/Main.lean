import LabVerifyLean

private def cleanStr (s : String) : String :=
  s.trimAscii.toString

private def parseBoolFlag (s : String) : Option Bool :=
  match cleanStr s with
  | "1" | "true" => some true
  | "0" | "false" => some false
  | _ => none

private def evalTsvLine (line : String) : Bool × String :=
  let trimmed := (line.trimAsciiEnd).toString
  let fields := trimmed.splitOn "\t"
  match fields with
  | ["MCP", tokEpStr, curEpStr, proofStr, frontStr, supStr] =>
    match (cleanStr tokEpStr).toNat?, (cleanStr curEpStr).toNat?,
          parseBoolFlag proofStr, parseBoolFlag frontStr, parseBoolFlag supStr with
    | some tokEp, some curEp, some proofOk, some isFront, some supOk =>
      let env : LabVerifyLean.McpHardwareEnvelope :=
        { tokenEpoch := tokEp
          currentDeckEpoch := curEp
          leanProofValid := proofOk
          isFrontierException := isFront
          humanSupervisorSign := supOk }
      match LabVerifyLean.checkMcpHardwareCall env with
      | none => (true, "OK\tmcp\tauthorized")
      | some v => (false, s!"REJECT\tmcp\t{v.rule}\t{v.detail}")
    | _, _, _, _, _ =>
      (false, "REJECT\tmcp\tinvalid_tsv_fields\tmalformed integer or boolean field in MCP TSV line")
  | _ =>
    (false, "REJECT\tmcp\tinvalid_tsv_command\texpected 6-column MCP TSV line")

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--batch-tsv"] =>
    let stdin ← IO.getStdin
    let input ← stdin.readToEnd
    let rawLines := input.splitOn "\n"
      |>.map cleanStr
      |>.filter (fun s => !s.isEmpty)
    if rawLines.isEmpty then
      IO.println "REJECT\tmcp\tempty_batch\tno TSV lines provided"
      return 1
    let mut allOk := true
    for ln in rawLines do
      let (ok, msg) := evalTsvLine ln
      IO.println msg
      if !ok then
        allOk := false
    return if allOk then 0 else 1
  | ["--self-check"] =>
    IO.println "OK\tself_check\tLabVerifyLean"
    return 0
  | _ =>
    IO.eprintln "Usage: lab-verify-lean [--batch-tsv | --self-check]"
    return 2
