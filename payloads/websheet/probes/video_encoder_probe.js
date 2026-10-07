/**
 * WebSheet Video Hardware Acceleration & Media Subsystem Probe.
 * Tests WebCodecs VideoEncoder and hardware acceleration reachability.
 * Registers as __L0FCK_STAGE4_RUNNERS.video_encoder_probe
 */
(function () {
  'use strict';

  var CODECS_TO_TEST = [
    { name: 'H264_Baseline', codec: 'avc1.42001E', width: 640, height: 480 },
    { name: 'H264_High', codec: 'avc1.640028', width: 1920, height: 1080 },
    { name: 'HEVC_Main', codec: 'hvc1.1.6.L93.B0', width: 1920, height: 1080 },
    { name: 'HEVC_Main10', codec: 'hvc1.2.4.L120.B0', width: 1920, height: 1080 }
  ];

  async function probeWebCodecs() {
    var hasWebCodecs = typeof window.VideoEncoder === 'function';
    if (!hasWebCodecs) {
      return { supported: false, reason: 'VideoEncoder not exposed on window' };
    }

    var codecResults = {};
    for (var i = 0; i < CODECS_TO_TEST.length; i++) {
      var item = CODECS_TO_TEST[i];
      try {
        var support = await VideoEncoder.isConfigSupported({
          codec: item.codec,
          width: item.width,
          height: item.height,
          hardwareAcceleration: 'prefer-hardware'
        });
        codecResults[item.name] = {
          supported: support.supported,
          hardwareAcceleration: (support.config && support.config.hardwareAcceleration) || 'unknown'
        };
      } catch (e) {
        codecResults[item.name] = { supported: false, error: e.message };
      }
    }

    // Attempt test frame encoding if supported
    var frameEncoded = false;
    try {
      var testConfig = {
        codec: 'avc1.42001E',
        width: 128,
        height: 128,
        bitrate: 500000,
        hardwareAcceleration: 'prefer-hardware'
      };
      var encoder = new VideoEncoder({
        output: function () { frameEncoded = true; },
        error: function () { /* handled */ }
      });
      encoder.configure(testConfig);

      var canvas = document.createElement('canvas');
      canvas.width = 128;
      canvas.height = 128;
      var ctx2d = canvas.getContext('2d');
      if (ctx2d) {
        ctx2d.fillStyle = '#00ff00';
        ctx2d.fillRect(0, 0, 128, 128);
      }

      if (typeof VideoFrame === 'function') {
        var frame = new VideoFrame(canvas, { timestamp: 0 });
        encoder.encode(frame, { keyFrame: true });
        frame.close();
        await encoder.flush();
      }
      encoder.close();
    } catch (encErr) {
      // Record any exception during pipeline execution
    }

    return {
      supported: true,
      codecs: codecResults,
      sample_frame_encoded: frameEncoded
    };
  }

  function probeMediaRecorder() {
    var hasMediaRecorder = typeof window.MediaRecorder === 'function';
    if (!hasMediaRecorder) {
      return { supported: false, reason: 'MediaRecorder not exposed' };
    }
    var types = [
      'video/mp4;codecs=avc1',
      'video/mp4;codecs=hevc',
      'video/mp4',
      'video/webm;codecs=vp8'
    ];
    var supportMap = {};
    types.forEach(function (t) {
      supportMap[t] = MediaRecorder.isTypeSupported(t);
    });
    return { supported: true, types: supportMap };
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.video_encoder_probe = function (ctx) {
    if (ctx && ctx.log) ctx.log('running video_encoder_probe...');

    return Promise.all([probeWebCodecs(), Promise.resolve(probeMediaRecorder())])
      .then(function (res) {
        var payload = {
          webcodecs: res[0],
          media_recorder: res[1],
          has_canvas_capture: typeof HTMLCanvasElement.prototype.captureStream === 'function',
          ts: Date.now()
        };
        if (ctx && ctx.log) ctx.log('video probe completed: ' + JSON.stringify(payload));
        return ctx.report('video_encoder_probe', 'ok', JSON.stringify(payload));
      })
      .catch(function (err) {
        return ctx.report('video_encoder_probe', 'error', err && err.message ? err.message : String(err));
      });
  };
})();
