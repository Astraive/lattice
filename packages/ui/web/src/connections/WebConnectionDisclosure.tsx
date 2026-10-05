export function WebConnectionDisclosure() {
  return (
    <p className="field-hint">
      BroadcastChannel is limited to same-origin open tabs. WebRTC sends signed event bytes directly
      between browsers; every received event still passes Core authorization, signature, MLS and
      generation checks. Transport acceptance is not recipient delivery.
    </p>
  );
}
