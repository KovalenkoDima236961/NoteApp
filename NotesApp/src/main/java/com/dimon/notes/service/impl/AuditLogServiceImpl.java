package com.dimon.notes.service.impl;

import com.dimon.notes.models.AuditLog;
import com.dimon.notes.models.Note;
import com.dimon.notes.repositories.AuditLogRepository;
import com.dimon.notes.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    @Autowired
    AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Note note) {
        AuditLog log = new AuditLog();
        log.setAction("CREATE");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimeStamp(LocalDateTime.now());
        auditLogRepository.save(log);

    }

    @Override
    public void logNoteUpdate(String username, Note note) {
        AuditLog log = new AuditLog();
        log.setAction("UPDATE");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimeStamp(LocalDateTime.now());
        auditLogRepository.save(log);

    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog log = new AuditLog();
        log.setAction("DELETE");
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setTimeStamp(LocalDateTime.now());
        auditLogRepository.save(log);

    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsForNoteId(Long id) {
        return auditLogRepository.findByNoteId(id);
    }
}
