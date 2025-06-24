/**
 * @name Methods and constructors invoked by fuzzerTestOneInput
 * @description This query finds all methods and constructors that could be invoked by the
 *              fuzzerTestOneInput harness, up to 3 layers deep.
 * @kind table
 * @id java/fuzzer-invoked-methods
 */

import java

/*from Method ma
where
  ma.getDeclaringType().hasName("ValidateVectorTypeVisitor") and
  ma.getName() = "visit" and
  ma.getNumberOfParameters() > 0
select ma, ma.getReturnType(), ma.getLocation()*/

predicate entryPoint(Callable c) {
//   (
//     c.hasName("validateFull") and c.getDeclaringType().getName() = "ValueVectorUtility"
//   ) or
//   (c.hasName("validate") and
//   c.getDeclaringType().getName() = "ValueVectorUtility" and
//   c.getNumberOfParameters() = 1)
  c.hasName("fuzzerTestOneInput") and
  c.getNumberOfParameters() = 1
}

predicate reachableAtDepth(Callable caller, Callable callee, int depth) {
  // Base case: the entry point of the fuzzer at depth 0.
  // It is identified by its name and signature.
  depth = 0 and
  entryPoint(caller) and
  caller.polyCalls(callee)
  or
  // Recursive step: a method or constructor `c` called by a `caller`
  // that is already reachable.
  exists(Callable mid_caller, int prevDepth |
    depth = prevDepth + 1 and
    prevDepth < 9 and
    reachableAtDepth(_, mid_caller, prevDepth) and
    // `polyCalls` resolves virtual calls to all possible targets.
    mid_caller.polyCalls(callee) and
    caller = mid_caller
  )
}

string maybeGetBodyLoc(Callable c) {
    result = c.getBody().getLocation().toString() or 
             not exists(c.getBody()) and result = "<none>"
}

string maybeGetRelativePath(File f) {
    result = f.getRelativePath() or
             not exists(f.getRelativePath()) and result = "<none>"
}

from Callable caller, Callable c, int depth, string bodyLocation, string file
where
  reachableAtDepth(caller, c, depth) and
  depth >= 0 and
  maybeGetBodyLoc(c) = bodyLocation and
  maybeGetRelativePath(c.getLocation().getFile()) = file
  select c.getName() as name,
    c.getSignature() as signature,
    c.getStringSignature() as simpleSignature,
    caller.getQualifiedName() as callerFqn,
    caller.getSignature() as callerSignature,
    caller.getLocation().toString() as callerLocation,
    depth,
    c.getQualifiedName() as fqn,
    file,
    c.getLocation().getStartLine() as startLine,
    c.getLocation().getEndLine() as endLine,
    c.getLocation().getNumberOfLines() as numberOfLines,
    bodyLocation
    //(Constructor)c as isConstructor,
    //caller.getACallSite(c) as callSite
order by fqn

// from Callable c where exists(Callable ep | ep.polyCalls(c) and entryPoint(ep)) select c.